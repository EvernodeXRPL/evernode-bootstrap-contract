#ifndef _SA_BOOTSTRAP_CONTRACT_
#define _SA_BOOTSTRAP_CONTRACT_

#include "hotpocket_contract.h"
#include <jsoncons/json.hpp>
#include <jsoncons_ext/bson/bson.hpp>

void create_response_message(std::vector<uint8_t> &msg, std::string_view type, std::string_view message);

#endif
