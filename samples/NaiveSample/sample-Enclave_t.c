#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_ocall_add_t {
	int ms_retval;
	int* ms_ptr1;
	int* ms_ptr2;
	size_t ms_size;
} ms_ocall_add_t;

static sgx_status_t SGX_CDECL sgx_ecall_ice(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ice_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ice_t* ms = SGX_CAST(ms_ecall_ice_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ecall_ice(ms->ms_a, ms->ms_b);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_buf(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_buf_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_buf_t* ms = SGX_CAST(ms_ecall_buf_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_size = ms->ms_size;
	size_t _len_ptr = _tmp_size * sizeof(int);
	int* _in_ptr = NULL;

	if (sizeof(*_tmp_ptr) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_ptr))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ptr != NULL && _len_ptr != 0) {
		if ( _len_ptr % sizeof(*_tmp_ptr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ptr = (int*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ptr, _len_ptr, _tmp_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_buf(_in_ptr, _tmp_size);
	if (_in_ptr) {
		if (memcpy_s(_tmp_ptr, _len_ptr, _in_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ptr) free(_in_ptr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_buf2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_buf2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_buf2_t* ms = SGX_CAST(ms_ecall_buf2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_ptr = ms->ms_ptr;
	size_t _tmp_size = ms->ms_size;
	size_t _len_ptr = _tmp_size * sizeof(int);
	int* _in_ptr = NULL;
	int* _tmp_ptr2 = ms->ms_ptr2;
	size_t _tmp_size2 = ms->ms_size2;
	size_t _len_ptr2 = _tmp_size2 * sizeof(int);
	int* _in_ptr2 = NULL;

	if (sizeof(*_tmp_ptr) != 0 &&
		(size_t)_tmp_size > (SIZE_MAX / sizeof(*_tmp_ptr))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_ptr2) != 0 &&
		(size_t)_tmp_size2 > (SIZE_MAX / sizeof(*_tmp_ptr2))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_ptr, _len_ptr);
	CHECK_UNIQUE_POINTER(_tmp_ptr2, _len_ptr2);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ptr != NULL && _len_ptr != 0) {
		if ( _len_ptr % sizeof(*_tmp_ptr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ptr = (int*)malloc(_len_ptr);
		if (_in_ptr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ptr, _len_ptr, _tmp_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ptr2 != NULL && _len_ptr2 != 0) {
		if ( _len_ptr2 % sizeof(*_tmp_ptr2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ptr2 = (int*)malloc(_len_ptr2);
		if (_in_ptr2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ptr2, _len_ptr2, _tmp_ptr2, _len_ptr2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_buf2(_in_ptr, _tmp_size, _in_ptr2, _tmp_size2);
	if (_in_ptr) {
		if (memcpy_s(_tmp_ptr, _len_ptr, _in_ptr, _len_ptr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_ptr2) {
		if (memcpy_s(_tmp_ptr2, _len_ptr2, _in_ptr2, _len_ptr2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ptr) free(_in_ptr);
	if (_in_ptr2) free(_in_ptr2);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_ice, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_buf, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_buf2, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};

typedef struct buf_meta_t {
	size_t offset;
	size_t size;
	int in_out;
} buf_meta_t;

typedef struct param_meta_t {
	void* ms;
	size_t size;
	buf_meta_t* arr;
	size_t arr_size;
	size_t ret_offset;
	size_t ret_size;
} param_meta_t;

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;



	ocalloc_size += sizeof(param_meta_t);
	ocalloc_size += 1 * sizeof(buf_meta_t);

	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	param_meta_t* ms_param_meta = (param_meta_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(param_meta_t));
	ocalloc_size -= sizeof(param_meta_t);
	buf_meta_t* ms_buf_meta = (buf_meta_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + 1 * sizeof(buf_meta_t));
	ocalloc_size -= 1 * sizeof(buf_meta_t);
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	

	ms_buf_meta[0].in_out = 1;
	ms_buf_meta[0].offset = (unsigned char*)(&(ms->ms_str)) - (unsigned char*)(ms);
	ms_buf_meta[0].size = _len_str;


	ms_param_meta->ms = ms;
	ms_param_meta->size = sizeof(*ms);
	ms_param_meta->arr = ms_buf_meta;
	ms_param_meta->arr_size = 1;
	ms_param_meta->ret_size = 0;
	ms_param_meta->ret_offset = 0;

	status = sgx_ocall(0, ms_param_meta);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_add(int* retval, int* ptr1, int* ptr2, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ptr1 = size * sizeof(int);
	size_t _len_ptr2 = size * sizeof(int);

	ms_ocall_add_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_add_t);
	void *__tmp = NULL;



	ocalloc_size += sizeof(param_meta_t);
	ocalloc_size += 2 * sizeof(buf_meta_t);
	void *__tmp_ptr1 = NULL;
	void *__tmp_ptr2 = NULL;

	CHECK_ENCLAVE_POINTER(ptr1, _len_ptr1);
	CHECK_ENCLAVE_POINTER(ptr2, _len_ptr2);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ptr1 != NULL) ? _len_ptr1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ptr2 != NULL) ? _len_ptr2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	param_meta_t* ms_param_meta = (param_meta_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(param_meta_t));
	ocalloc_size -= sizeof(param_meta_t);
	buf_meta_t* ms_buf_meta = (buf_meta_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + 2 * sizeof(buf_meta_t));
	ocalloc_size -= 2 * sizeof(buf_meta_t);
	ms = (ms_ocall_add_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_add_t));
	ocalloc_size -= sizeof(ms_ocall_add_t);

	if (ptr1 != NULL) {
		ms->ms_ptr1 = (int*)__tmp;
		__tmp_ptr1 = __tmp;
		if (_len_ptr1 % sizeof(*ptr1) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_ptr1, ocalloc_size, ptr1, _len_ptr1)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ptr1);
		ocalloc_size -= _len_ptr1;
	} else {
		ms->ms_ptr1 = NULL;
	}
	
	if (ptr2 != NULL) {
		ms->ms_ptr2 = (int*)__tmp;
		__tmp_ptr2 = __tmp;
		if (_len_ptr2 % sizeof(*ptr2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_ptr2, ocalloc_size, ptr2, _len_ptr2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ptr2);
		ocalloc_size -= _len_ptr2;
	} else {
		ms->ms_ptr2 = NULL;
	}

	ms->ms_size = size;

	ms_buf_meta[0].in_out = 3;
	ms_buf_meta[0].offset = (unsigned char*)(&(ms->ms_ptr1)) - (unsigned char*)(ms);
	ms_buf_meta[0].size = _len_ptr1;

	ms_buf_meta[1].in_out = 3;
	ms_buf_meta[1].offset = (unsigned char*)(&(ms->ms_ptr2)) - (unsigned char*)(ms);
	ms_buf_meta[1].size = _len_ptr2;

	
	ms_param_meta->ms = ms;
	ms_param_meta->size = sizeof(*ms);
	ms_param_meta->arr = ms_buf_meta;
	ms_param_meta->arr_size = 2;
	ms_param_meta->ret_size = sizeof(int);
	ms_param_meta->ret_offset = 0;

	status = sgx_ocall(1, ms_param_meta);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (ptr1) {
			if (memcpy_s((void*)ptr1, _len_ptr1, __tmp_ptr1, _len_ptr1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ptr2) {
			if (memcpy_s((void*)ptr2, _len_ptr2, __tmp_ptr2, _len_ptr2)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

