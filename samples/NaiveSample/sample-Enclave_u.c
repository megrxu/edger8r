/*
    trusted {
        public int ecall_ice(int a, int b);
        public int ecall_buf([in, out, count=size] int *ptr, size_t size);
        public int ecall_buf2([in, out, count=size] int *ptr, size_t size, [in, out, count=size2] int *ptr2, size_t size2);
    };
*/

#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_ice_t {
	int ms_retval;
	int ms_a;
	int ms_b;
} ms_ecall_ice_t;

typedef struct ms_ecall_buf_t {
	int ms_retval;
	int* ms_ptr;
	size_t ms_size;
} ms_ecall_buf_t;

typedef struct ms_ecall_buf2_t {
	int ms_retval;
	int* ms_ptr;
	size_t ms_size;
	int* ms_ptr2;
	size_t ms_size2;
} ms_ecall_buf2_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};

typedef struct buf_meta_t {
	size_t 	offset;
	size_t 	size;
	int   	in_out;
}buf_meta_t;

typedef struct param_meta_t {
	void *ms;     // addr of param struct
	size_t size;  // size of param struct
	buf_meta_t *arr;
	size_t arr_size;

	size_t ret_offset;
	size_t ret_size;
} param_meta_t;

sgx_status_t ecall_ice(sgx_enclave_id_t eid, int* retval, int a, int b)
{
	sgx_status_t status;
	ms_ecall_ice_t ms;
	ms.ms_a = a;
	ms.ms_b = b;

	param_meta_t ms_param_meta;
	ms_param_meta.ms = &ms;
	ms_param_meta.size = sizeof(ms);
	ms_param_meta.arr = NULL;
	ms_param_meta.arr_size = 0;
	ms_param_meta.ret_size = sizeof(int);
	ms_param_meta.ret_offset = 0;	

	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms_param_meta);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_buf(sgx_enclave_id_t eid, int* retval, int* ptr, size_t size)
{
	sgx_status_t status;
	ms_ecall_buf_t ms;
	ms.ms_ptr = ptr;
	ms.ms_size = size;

	#define  PTR_CNT 1
	buf_meta_t buf_meta[PTR_CNT];
	
	#define ptr_INDEX  0
	buf_meta[ptr_INDEX].in_out = 3;
	buf_meta[ptr_INDEX].offset = (unsigned char *)(&ms.ms_ptr) - (unsigned char *)(&ms);
	buf_meta[ptr_INDEX].size = size * sizeof(int);

	param_meta_t ms_param_meta;
	ms_param_meta.ms = &ms;
	ms_param_meta.size = sizeof(ms);
	ms_param_meta.arr = buf_meta;
	ms_param_meta.arr_size = PTR_CNT;
	ms_param_meta.ret_size = sizeof(int);
	ms_param_meta.ret_offset = 0;

	unsigned char *ms_ptr = &ms;
	unsigned char **tmp_ptrptr = (ms_ptr + sizeof(int));
	unsigned char *tmp_ptr = *tmp_ptrptr;

    printf("ms: %lu - %p - %p\n", buf_meta[ptr_INDEX].offset, tmp_ptrptr, tmp_ptr);
	printf("ms: %p - %p\n", &ms, ptr);

	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms_param_meta);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	
	#undef	PRT_CNT
	#undef  ptr_INDEX

	return status;
}

sgx_status_t ecall_buf2(sgx_enclave_id_t eid, int* retval, int* ptr, size_t size, int* ptr2, size_t size2)
{
	sgx_status_t status;
	ms_ecall_buf2_t ms;
	ms.ms_ptr = ptr;
	ms.ms_size = size;
	ms.ms_ptr2 = ptr2;
	ms.ms_size2 = size2;

	#define  PTR_CNT 2
	buf_meta_t buf_meta[PTR_CNT];
	
	#define ptr_INDEX  0
	buf_meta[ptr_INDEX].in_out = 3;
	buf_meta[ptr_INDEX].offset = (unsigned char *)(&ms.ms_ptr) - (unsigned char *)(&ms);
	buf_meta[ptr_INDEX].size = size * sizeof(int);

	#define ptr2_INDEX  1
	buf_meta[ptr2_INDEX].in_out = 3;
	buf_meta[ptr2_INDEX].offset = (unsigned char *)(&ms.ms_ptr2) - (unsigned char *)(&ms);
	buf_meta[ptr2_INDEX].size = size2 * sizeof(int);


	param_meta_t ms_param_meta;
	ms_param_meta.ms = &ms;
	ms_param_meta.size = sizeof(ms);
	ms_param_meta.arr = buf_meta;
	ms_param_meta.arr_size = PTR_CNT;
	ms_param_meta.ret_size = sizeof(int);
	ms_param_meta.ret_offset = 0;

	// unsigned char *ms_ptr = &ms;
	// unsigned char **tmp_ptrptr = (ms_ptr + sizeof(int));
	// unsigned char *tmp_ptr = *tmp_ptrptr;

    // printf("ms: %lu - %p - %p\n", buf_meta[ptr_INDEX].offset, tmp_ptrptr, tmp_ptr);
	// printf("ms: %p - %p\n", &ms, ptr);


	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms_param_meta);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

