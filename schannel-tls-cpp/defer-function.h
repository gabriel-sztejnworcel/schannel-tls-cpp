#pragma once

#include <functional>

class DeferFunction
{
public:
    DeferFunction(std::function<void()> deferred_func);
    ~DeferFunction();

private:
    std::function<void()> deferred_func_;
};
