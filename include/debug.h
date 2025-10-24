
#ifndef CRYPTOMAI_DEBUG_H
#define CRYPTOMAI_DEBUG_H

#define DEBUG
#ifdef DEBUG
constexpr bool I_WANT_CHECK_KEY = false;
#endif
#ifndef DEBUG
constexpr bool I_WANT_CHECK_KEY = true;
#endif

#endif  // CRYPTOMAI_DEBUG_H
