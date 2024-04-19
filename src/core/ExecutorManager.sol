// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import {IHook, IExecutor} from "../interfaces/IERC7579Modules.sol";
import {ModuleLib} from "../utils/ModuleLib.sol";
import {EXECUTOR_MANAGER_STORAGE_SLOT} from "../types/Constants.sol";

abstract contract ExecutorManager {
    struct ExecutorConfig {
        IHook hook; // address(1) : hook not required, address(0) : validator not installed
    }

    struct ExecutorStorage {
        mapping(IExecutor => ExecutorConfig) executorConfig;
    }

    function executorConfig(IExecutor executor) external view returns (ExecutorConfig memory) {
        return _executorConfig(executor);
    }

    function _executorConfig(IExecutor executor) internal view returns (ExecutorConfig storage config) {
        ExecutorStorage storage es;
        bytes32 slot = EXECUTOR_MANAGER_STORAGE_SLOT;
        assembly {
            es.slot := slot
        }
        config = es.executorConfig[executor];
    }

    function _installExecutor(IExecutor executor, bytes calldata executorData, IHook hook) internal {
        // NOTE: if there is no hook passed in, then we will set the hook to address(1)
        // NOTE: if there is a hook passed, then we will set the hook to the passed hook
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }

        // NOTE: a struct with one value (hook)
        ExecutorConfig storage config = _executorConfig(executor);

        // NOTE: 1. store executor in state
        // QUESTION: where is this referenced for validation?
        // ANSWER: in the kernel in the executeFromExecutor function
        config.hook = hook;

        // NOTE: 2. call function to install on executor
        executor.onInstall(executorData);
    }

    function _installExecutorWithoutInit(IExecutor executor, IHook hook) internal {
        if (address(hook) == address(0)) {
            hook = IHook(address(1));
        }
        ExecutorConfig storage config = _executorConfig(executor);
        config.hook = hook;
    }

    function _uninstallExecutor(IExecutor executor, bytes calldata executorData) internal returns (IHook hook) {
        ExecutorConfig storage config = _executorConfig(executor);
        hook = config.hook;
        config.hook = IHook(address(0));
        ModuleLib.uninstallModule(address(executor), executorData);
    }
}
