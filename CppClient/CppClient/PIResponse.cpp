#include "PIResponse.h"

bool PIResponse::PushAvailable()
{
    for (auto& challenge : challenges)
    {
        if (challenge.type == "push")
        {
            return true;
        }
    }
    return false;
}

std::string PIResponse::PushMessage()
{
    for (auto& challenge : challenges)
    {
        if (challenge.type == "push")
        {
            return challenge.message;
        }
    }
    return "";
}
