#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <string>
#include <vector>
#include <iostream>
#include <libdrakvuf/ntstatus.h>
#include <libinjector/libinjector.h>
#include <vector>
#include <mutex>
#include <memory>
#include <queue>
#include <condition_variable>
#include <thread>

#include "win.h"


using namespace syscalls_ns;
    
    
std::map<std::pair<uint64_t, addr_t>, std::unique_ptr<libhook::ReturnHook>> syscall_ret_hooks;


constexpr size_t  MAX_BUCKETS = 1024;

std::array<PipeLineStructre,MAX_BUCKETS> syscall_result_aggregate;

volatile size_t id = 0 ; 

constexpr std::array<const char *,1> BLACK_LIST_NTOS = {
    "NtQueryPerformanceCounter"
} ;




constexpr size_t BATCH_SIZE = 500000 * 2;
constexpr size_t MAX_SLOTS = 10; // "X" slots to prevent blocking
class GlobalDumpManager {
private:
    std::queue<std::unique_ptr<std::vector<SyscallTraceResults>>> slot_queue;
    std::mutex mtx;
    std::condition_variable cv;
    std::thread consumer_thread;
    bool shut_down = false;

    void consumer_loop() {
        while (true) {
            std::unique_ptr<std::vector<SyscallTraceResults>> work_item;
            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [this] { return !slot_queue.empty() || shut_down; });
                if (shut_down && slot_queue.empty()) return;
                work_item = std::move(slot_queue.front());
                slot_queue.pop();
            }

            if (work_item && !work_item->empty()) {
                std::fwrite(work_item->data(), sizeof(SyscallTraceResults), work_item->size(), stdout);
                std::fflush(stdout);
            }
        }
    }

public:
    GlobalDumpManager() {
        consumer_thread = std::thread(&GlobalDumpManager::consumer_loop, this);
    }

    ~GlobalDumpManager() {
        {
            std::lock_guard<std::mutex> lock(mtx);
            shut_down = true;
        }
        cv.notify_all();
        if (consumer_thread.joinable()) consumer_thread.join();
    }

    // THE MISSING LINK: The TLS threads call this
    void process_full_buffer(std::unique_ptr<std::vector<SyscallTraceResults>> full_buffer) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            
            if (slot_queue.size() < MAX_SLOTS) {
                slot_queue.push(std::move(full_buffer));
            } else {
                std::cerr << "--- OVERCLOCK FAILED ----" << std::endl;
                return; // if we reach here we are on a problem
            }
        }
        cv.notify_one(); 
    }

    static GlobalDumpManager& getInstance() {
        static GlobalDumpManager instance;
        return instance;
    }
};
// Thread-local management
struct TLSProducer {
    std::unique_ptr<std::vector<SyscallTraceResults>> local_buffer;

    TLSProducer() {
        local_buffer = std::make_unique<std::vector<SyscallTraceResults>>();
        local_buffer->reserve(BATCH_SIZE);
    }

    void push(const SyscallTraceResults& result) {
        local_buffer->push_back(result);

        if (local_buffer->size() >= BATCH_SIZE) {
            // TRANSFER: Move local pointer to the global manager
            GlobalDumpManager::getInstance().process_full_buffer(std::move(local_buffer));
            
            // RE-ALLOCATE: Prepare a fresh buffer for this thread
            local_buffer = std::make_unique<std::vector<SyscallTraceResults>>();
            local_buffer->reserve(BATCH_SIZE);
        }
    }
};

// The thread-local singleton
thread_local TLSProducer producer;


event_response_t refernce_handle_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info){
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t access = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t access_mode = drakvuf_get_function_argument(drakvuf, info, 3);


    const proc_data_t* proc_data = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS ? &info->attached_proc_data : &info->proc_data;
    SyscallTraceResults* obj = nullptr;

    size_t key = proc_data->tid;
    auto it = syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].find(key);
    if (it != syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].end()) {
        obj = &it->second;
    }
    
    if(obj){
        if(obj->handle_1_val == 1337){
            obj->handle_1_val =handle;
            obj->handle_1_access_mode = access_mode; 
            obj->handle_1_access = access;
        }  
        else if (obj->handle_2_val == 1337){
            obj->handle_2_val = handle;
            obj->handle_2_access_mode = access_mode; 
            obj->handle_2_access = access;
        }  
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t syscall_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto w = get_trap_params<wrapper_t>(info);
    privilege_mode_t mode;
    if (drakvuf_get_current_thread_previous_mode(drakvuf, info, &mode))
    {
        mode = privilege_mode_t::MAXIMUM_MODE ;
    }
    const proc_data_t* proc_data = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS ? &info->attached_proc_data : &info->proc_data;
    SyscallTraceResults result;

    result.current_time = info->timestamp;

    size_t process_name_length = strlen(proc_data->name);
    if(process_name_length  >= sizeof(result.process_name))
        memcpy(result.process_name, 
            proc_data->name + process_name_length - sizeof(result.process_name),
            sizeof( result.process_name));
    else
        memcpy(result.process_name, 
            proc_data->name,
           process_name_length);

    result.syscall_num = w->num;
    result.tid = proc_data->tid;
    result.pid = proc_data->pid;
    result.syscall_mode = mode;

    size_t key = proc_data->tid;

    auto [it,inserted] = syscall_result_aggregate[(proc_data->tid >> 2)% MAX_BUCKETS].try_emplace(key,result);
    
    if(!inserted){
        producer.push(it->second);
        syscall_result_aggregate[(it->second.tid>>2) % MAX_BUCKETS].erase(it);
        syscall_result_aggregate[(proc_data->tid >> 2)% MAX_BUCKETS].emplace(key,result);
    }
        
    return VMI_EVENT_RESPONSE_NONE;
}

bool win_syscalls::trap_syscall_table_entries(drakvuf_t drakvuf, vmi_instance_t vmi, addr_t cr3, bool ntos, addr_t base, std::array<addr_t, 2> _sst, json_object* json)
{
    unsigned int syscall_count = ntos ? NUM_SYSCALLS_NT : NUM_SYSCALLS_WIN32K;
    const syscall_t** definitions = ntos ? nt : win32k;

    symbols_t* symbols = json ? json_get_symbols(json) : NULL;

    int32_t* table = (int32_t*)g_try_malloc0(_sst[1] * sizeof(int32_t));
    if ( !table )
    {
        drakvuf_free_symbols(symbols);
        return false;
    }

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = cr3;
    ctx.addr = _sst[0];
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, _sst[1] * sizeof(uint32_t), table, NULL) )
    {
        drakvuf_free_symbols(symbols);
        g_free(table);
        return false;
    }

    for ( addr_t syscall_num = 0; syscall_num < _sst[1]; syscall_num++ )
    {
        long offset = 0;
        addr_t syscall_va;

        if ( !this->is32bit )
        {
            offset = table[syscall_num] >> 4;
            syscall_va = _sst[0] + offset;
        }
        else
            syscall_va = table[syscall_num];

        addr_t rva = syscall_va - base;
        if ( this->is32bit )
            rva = static_cast<uint32_t>(rva);

        const struct symbol* symbol = nullptr;
        const syscall_t* definition = nullptr;
        if ( symbols )
        {
            for (unsigned int z=0; z < symbols->count; z++)
            {
                if ( symbols->symbols[z].rva == rva )
                {
                    symbol = &symbols->symbols[z];

                    for (unsigned int d=0; d < syscall_count; d++)
                    {
                        if ( !strcmp(definitions[d]->name, symbol->name) )
                        {
                            definition = definitions[d];
                            break;
                        }
                    }
                    break;
                }
            }
        }
        const char* symbol_name = nullptr;
        bool skip_syscall_hook = false;
        for(size_t i = 0 ; i < BLACK_LIST_NTOS.size() ; i++){
            if(!strcmp(BLACK_LIST_NTOS[i],symbol->name))
                skip_syscall_hook = true;
        }
        if(skip_syscall_hook){
            continue;
        }
        if ( !symbol )
            continue;
    
        else if ( !definition )
        {
            gchar* tmp = g_strdup(symbol->name);
            this->strings_to_free = g_slist_prepend(this->strings_to_free, tmp);
            symbol_name = (const char*)tmp;
        }
        else
            symbol_name = definition->name;

        if ( !this->filter.empty() && ( !symbol_name || (this->filter.find(symbol_name) == this->filter.end())))
            continue;


        breakpoint_by_dtb_searcher bp;
        auto trap = this->register_trap<wrapper_t>(
                nullptr,
                syscall_cb,
                bp.for_virt_addr(syscall_va).for_dtb(cr3),
                symbol_name);

        if (!trap)
        {
            PRINT_DEBUG("Failed to trap syscall %lu @ 0x%lx\n", syscall_num, syscall_va);
            continue;
        }


        auto w = get_trap_params<wrapper_t>(trap);

        w->num = syscall_num;
        //w->type = ntos ? "nt" : "win32k";
        //w->sc = definition;
    }

    drakvuf_free_symbols(symbols);
    g_free(table);

    return true;
}

win_syscalls::win_syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output)
    : syscalls_base(drakvuf, config, output)
    , win32k_profile{ config->win32k_profile ?: "" }
{


    for(size_t i=0 ; i < MAX_BUCKETS;i++){
        ::syscall_result_aggregate[i].reserve(100); // reserve a lot of space ... more then ever needed
        ::syscall_result_aggregate[i].max_load_factor(0.7f);
    }


    auto vmi = vmi_lock_guard(drakvuf);

    if ( !this->is32bit )
    {
        system_service_table_x64 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x64), (void*)&_sst, NULL) )
        {
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }
    else
    {
        system_service_table_x86 _sst[2] = {};
        if ( VMI_FAILURE == vmi_read_ksym(vmi, "KeServiceDescriptorTableShadow", 2*sizeof(system_service_table_x86), (void*)&_sst, NULL) )
        {
            throw -1;
        }

        this->sst[0][0] = _sst[0].ServiceTable;
        this->sst[0][1] = _sst[0].ServiceLimit;
        this->sst[1][0] = _sst[1].ServiceTable;
        this->sst[1][1] = _sst[1].ServiceLimit;
    }

    addr_t dtb;
    if ( VMI_FAILURE == vmi_pid_to_dtb(vmi, 0, &dtb) )
    {
        throw -1;
    }
    if (!drakvuf_get_kernel_struct_member_rva(drakvuf, "_RTL_USER_PROCESS_PARAMETERS", "ImagePathName", &this->image_path_name))
    {
        throw -1;
    }
    if (!trap_syscall_table_entries(drakvuf, vmi, dtb, true, this->kernel_base, this->sst[0], vmi_get_kernel_json(vmi)))
    {
        throw -1;
    }
    this->offsets = (addr_t*)g_try_malloc0(__OFFSETX_MAX*sizeof(addr_t));
    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSETX_MAX, this->offsets)){
        throw -1;
    }
    if ( !drakvuf_get_kernel_struct_size(drakvuf, "_KTRAP_FRAME", &this->ktrap_frame_size) )
    {
        g_free(this->offsets);
        throw -1;
    }
   
    // For Faster Results...
    breakpoint_in_system_process_searcher bp;
    this->register_trap<wrapper_t>(
                nullptr,
                refernce_handle_hook_cb,
                bp.for_syscall_name("ObReferenceObjectByHandle"),
                "ObReferenceObjectByHandle");

   this->create_handle_hook = this->createSyscallHook("ObpCreateHandle", &win_syscalls::create_handle_hook_cb);
   this->close_handle_hook = this->createSyscallHook("ObCloseHandleTableEntry", &win_syscalls::close_handle_hook_cb);

}

event_response_t win_syscalls::create_handle_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t open_reason = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t return_handle_ptr = drakvuf_get_function_argument(drakvuf, info, 11);
    
    auto hook = createReturnHook<ObpCreateHandleResult>(info, &win_syscalls::create_handle_hook_ret_cb);
    auto params = libhook::GetTrapParams<ObpCreateHandleResult>(hook->trap_);
    
    params->return_handle_ptr = return_handle_ptr;
    params->open_reason = open_reason;

    auto hookID = make_hook_id(info, params->target_rsp);
    this->ret_hooks[hookID] = std::move(hook);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::create_handle_hook_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    
    auto params = libhook::GetTrapParams<ObpCreateHandleResult>(info);
    
    if (!params->verifyResultCallParams(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;
    
    size_t handle_val = INVALID_HANDLE_VALUE ; 

    ACCESS_CONTEXT(ctx);
    auto vmi = vmi_lock_guard(drakvuf);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = params->return_handle_ptr ;
    if ( VMI_FAILURE == vmi_read(vmi, &ctx, sizeof(handle_val), &handle_val, NULL) )
        return VMI_EVENT_RESPONSE_NONE;


    const proc_data_t* proc_data = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS ? &info->attached_proc_data : &info->proc_data;
    SyscallTraceResults* obj = nullptr;

    size_t key = proc_data->tid;
    auto it = syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].find(key);
    if (it != syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].end()) {
        obj = &it->second;
    }
    
    if(obj){
        obj->ret_handle = handle_val;
        obj->handle_operation = params->open_reason + 1; 
    }

    auto hookID = make_hook_id(info, params->target_rsp);
    ret_hooks.erase(hookID);
    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t win_syscalls::close_handle_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info){
    addr_t handle = drakvuf_get_function_argument(drakvuf, info, 4);
  
    const proc_data_t* proc_data = drakvuf_get_os_type(drakvuf) == VMI_OS_WINDOWS ? &info->attached_proc_data : &info->proc_data;
    SyscallTraceResults* obj = nullptr;
    size_t key = proc_data->tid;
    auto it = syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].find(key);
    if (it != syscall_result_aggregate[(proc_data->tid>>2) % MAX_BUCKETS].end()) {
        obj = &it->second;
    }

    if(obj != nullptr ){
        obj->closed_handle = handle;
    }


    return VMI_EVENT_RESPONSE_NONE;
}

win_syscalls::~win_syscalls()
{
    GSList* loop = this->strings_to_free;
    while (loop)
    {
        g_free(loop->data);
        loop = loop->next;
    }
    g_slist_free(this->strings_to_free);
}