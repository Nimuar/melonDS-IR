#ifndef IRMDNS_H
#define IRMDNS_H

#include <cstdint>

namespace melonDS::Platform
{

void IR_StartMDNS(uint16_t port = 8081);
void IR_StopMDNS();
void IR_PollMDNS();

} // namespace melonDS::Platform

#endif // IRMDNS_H
