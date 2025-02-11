#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <time.h>
#include <thread>
#include <vector>
#include <semaphore.h>
#include <omp.h>
#include <cmath>

#include "ABE/ABE2OD.h"
#include "pbc/pbc_test.h"
#include "PicoSHA2/picosha2.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
double abe_time_setup =0;
double abe_time_keygen =0;
double abe_time_enc =0;
double abe_time_t1 =0;
double abe_time_t2 =0;
double abe_time_dec = 0;
double transform1_start_time, transform1_end_time;
double transform2_start_time, transform2_end_time;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] =
{
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_MEMORY_MAP_FAILURE,
        "Failed to reserve memory for the enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if(ret == sgx_errlist[idx].err)
        {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        exit(-1);
    }
}

//以上内容都是必须的

/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/* ECall functions */




/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

     double start_time, end_time;//开始时间与结束时间
    // int result = initialize_enclave();//创建 Enclave

    // // 创建线程并启动
    // if (argc < 3) {
    //     std::cerr << "Error: Missing arguments.\n";
    //     return 1;
    // }    
    // const int num_tasks = std::atoi(argv[1]);//100 200 300 400 500
    // printf("epoch Num is %d \n", num_tasks);
    // int coreNum = omp_get_num_procs();//获得处理器个数
    // printf("Core Num max is %d \n", coreNum);
    // int cpu_number = atoi(argv[2]);//1 3 6 9 12
    // omp_set_num_threads(cpu_number);//指定并行区内线程个数
    // printf("Select  Core_Num is %d \n",cpu_number);
        // **参数检查**
    if (argc < 3) {
        cerr << "错误: 缺少参数。\n";
        cerr << "用法: " << argv[0] << " <任务数> <核心数>\n";
        cerr << "示例: " << argv[0] << " 100 4\n";
        return 1; // 返回错误码 1
    }

    // **解析命令行参数**
    const int num_tasks = std::atoi(argv[1]); // 任务数
    const int cpu_number = std::atoi(argv[2]); // CPU 核心数

    if (num_tasks <= 0 || cpu_number <= 0) {
        cerr << "错误: 任务数和核心数必须为正整数。\n";
        return 1;
    }

    // **获取 CPU 核心数**
    int coreNum = omp_get_num_procs();
    cout << "总核心数: " << coreNum << "\n";
    cout << "指定使用的核心数: " << cpu_number << "\n";

    // **设置 OpenMP 线程数**
    omp_set_num_threads(cpu_number);
    
    // **初始化 Enclave**
    int result = initialize_enclave();
    if (result != 0) {
        cerr << "错误: Enclave 初始化失败。\n";
        return 1;
    }
    step_1_enc();
    
    double t_sum = 0.0;

    start_time = omp_get_wtime(); 
    #pragma omp private(M, cipher_str, cipher_str_count, policy_len, tk_1_str, tk_1_str_count, key_len_tk_1, value_len_tk_1, umap_key_str_tk_1, umap_value_str_tk_1, each_str_counts_size_tk_1, each_str_counts_tk_1, tk_2_str, tk_2_str_count, key_len_tk_2, value_len_tk_2, umap_key_str_tk_2, umap_value_str_tk_2, each_str_counts_size_tk_2, each_str_counts_tk_2, hk_str, hk_str_count, dk_str, dk_str_count, ptc_str, ptc_str_count, tc_str, tc_str_count, transform1_start_time, transform1_end_time,t_start_time, t_end_time, transform2_start_time, transform2_end_time,wait_time) reduction(+:t_sum,abe_time_t1,abe_time_t2,abe_time_dec) schedule(dynamic)
    {
    double t_start_time = omp_get_wtime();
    #pragma omp parallel for 
    for (int i = 0; i < num_tasks; i++)
    {
        
        int id = omp_get_thread_num();
        step_2_transform1(id);
        #pragma omp critical
        {
            step_2_transform2(id);
            double t_end_time = omp_get_wtime();
            t_sum+=(t_end_time - t_start_time);
            //printf("[ 内核 %d ] 等待时间:%.4f ms\n", id,(t_end_time - t_start_time)*1000);
            step_3_dec(id);
        }
    }
    }
    #pragma omp barrier
    {
	    end_time = omp_get_wtime();
	    after(global_eid); //释放Enclave中的pairing
	    sgx_destroy_enclave(global_eid);// 销毁 Enclave
    }


    printf("%d次 t1(APP) 平均耗时:%.4f ms\n",num_tasks,(abe_time_t1/num_tasks)*1000);
    printf("%d次 t2(Enclave) 平均耗时:%.4f ms\n",num_tasks,(abe_time_t2/num_tasks)*1000);
    printf("%d次 dec 平均耗时:%.4f ms\n",num_tasks,(abe_time_dec/num_tasks)*1000);
    printf("%d次 多线程平均等待耗时:%.4f ms\n",num_tasks,(t_sum/num_tasks)*1000);
    printf("总耗时:%.4f ms\n",(end_time-start_time)*1000);
    printf("Info: successfully returned.\n");

    int numTasks = atoi(argv[1]);
    int maxTasksPerThread  = atoi(argv[2]);
    int taskTime = 240; // 假设每个任务运行时间（毫秒）
    double totalTime = 0.0; // 总等待时间

    #pragma omp parallel for reduction(+:totalTime)
    for (int i = 0; i < numTasks; ++i)
    {
        int threadId = i / maxTasksPerThread;
        int waitTime = threadId * taskTime; // 计算等待时间
        totalTime += waitTime;
    }

    double averageWaitTime = totalTime / numTasks; // 平均等待时间

    cout <<"任务数量:"<<numTasks<<" 内核数:"<<maxTasksPerThread<<" 理想平均等待时间：" << averageWaitTime << " 毫秒" <<'\n';

    return 0;
}

