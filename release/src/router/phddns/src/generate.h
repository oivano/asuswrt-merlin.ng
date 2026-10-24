#ifndef __GENERATE_H_ZHY_0505241025__
#define __GENERATE_H_ZHY_0505241025__

#define PH_CHALLENGE_MIN_LEN 10
#define PH_CHALLENGE_MAX_LEN 64


int GenerateCrypt(char *szUser, 
							char *szPassword, 
							char *szChallenge64, 
							int clientinfo,
							int embkey,
							char *szResult
							 );

#endif
