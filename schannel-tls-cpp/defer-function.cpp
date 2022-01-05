
#include "defer-function.h"

DeferFunction::DeferFunction(std::function<void()> deferred_func) :
    deferred_func_(deferred_func)
{

}

DeferFunction::~DeferFunction()
{
    deferred_func_();
}
