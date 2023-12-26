static int
sys_ipc_try_send(envid_t envid, uint32_t value, uintptr_t srcva, size_t size, int perm) {
    // LAB 9_Done: Your code here
    struct Env* env;
    if (envid2env(envid, &env, 0))
        return -E_BAD_ENV;

    if (!env->env_ipc_recving)
        return -E_IPC_NOT_RECV;

    if (srcva < MAX_USER_ADDRESS && env->env_ipc_dstva < MAX_USER_ADDRESS) {
        int res = map_region(&env->address_space, env->env_ipc_dstva, &curenv->address_space, srcva, PAGE_SIZE, perm | PROT_USER_);
        if (res) {
            env->env_ipc_recving = true;
            return res;
        }

        env->env_ipc_maxsz = MIN(size, env->env_ipc_maxsz);
        env->env_ipc_perm = perm;
    } else 
        env->env_ipc_perm = 0;

    env->env_ipc_value = value;
    env->env_ipc_from = curenv->env_id;
    env->env_ipc_recving = 0;
    env->env_status = ENV_RUNNABLE;
    return 0;
}