#ifndef _EXPRESS_VERIFY_H_
#define _EXPRESS_VERIFY_H_

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
	int magic_num;
	unsigned cur_time;	//��ǰʱ��
	int cookie_time;		//��Ч��
	unsigned level;		//level
	unsigned guid;			//guid
	unsigned filename;			//filename
	unsigned long long uin;			//uin
} musicStKey;

//int qqmusic_createTstreamKey(int magic_num , int cookie_time, unsigned level , string guid, char * pEncryptBuf, const int lBufSize);
int qqmusic_createTstreamKey(int magic_num , int cookie_time, unsigned level, const char* guid, char * pEncryptBuf, const int lBufSize);

//��֤key
// pEncryptData keyֵ
// lDataLen key����
/*flag��־:��Ӧ��λΪ1��ʾ���,0��ʾ�����
��һλ���magicnum
�ڶ�λ���ʱ���
����λ���user level
����λ���guid
*/

int qqmusic_verify_weak_TstreamKey(int magic_num, const char* guid , const char *pEncryptData, const int lDataLen);
int qqmusic_verify_strong_TstreamKey(int magic_num, const char* guid, const char* filename, unsigned long long uin, const char * pEncryptData, const int lDataLen, int skipFileCheck);

int qqmusic_create_weak_express_key(const char* guid, int cookie_time, char* pEncryptBuf, const int lBufSize);

int qqmusic_create_strong_express_key(const char* guid, const char* filename, unsigned long long uin, const char* qqkey, const char* downkey, int from_tag, int cookie_time, char* pEncryptBuf, const int lBufSize);

/** verify qq music key
 * @param vkey encrypted key
 * @param vkeyLen length of vkey
 * @param magic_num predefined magic number
 * @param guid device unique id

 * for strong verification only.
 * @param filename file name
 * @param uin uin from cookie
 * @param qqkey qqkey from cookie
 * @param donwkey donwkey from cookie
 * @param from_tag from cookie

 * @returns 0: successful  non-zero: failed
 */
int qqmusic_verify_express_key(const char* vkey, int vkeyLen, int magic_num, const char* guid, const char* filename, unsigned long long uin, int from_tag);

/** create CDN server verification key
 * @param guid : device unique id
 * @param pEncryptBuf : output param. encrypted value fo guid.
 * @param lBufSize: must be 32

 * @returns 0: successful  non-zero: failed
 */
int qqmusic_create_server_key(const char* guid, char* pEncryptBuf, const int lBufSize);

#ifdef __cplusplus
} /* extern "C" */
#endif


#endif /*_EXPRESS_VERIFY_H_*/
