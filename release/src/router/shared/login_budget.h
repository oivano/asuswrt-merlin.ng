#ifndef __LOGIN_BUDGET_H__
#define __LOGIN_BUDGET_H__

enum login_budget_scope {
	LOGIN_BUDGET_LAN = 0,
	LOGIN_BUDGET_WAN,
	LOGIN_BUDGET_UNKNOWN,
	LOGIN_BUDGET_SSH
};

int shared_login_attempt_admit(enum login_budget_scope scope, unsigned int *retry_after);

#endif
