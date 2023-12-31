/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "skissm/log_code.h"

static const char * LOG_CODE_STRINGS[] = {
    "DEBUG_LOG",
    "BAD_ACCOUNT",
    "BAD_SESSION",
    "BAD_GROUP_SESSION",
    "BAD_SIGNATURE",
    "BAD_PRE_KEY_BUNDLE",
    "BAD_SERVER_MESSAGE",
    "BAD_REMOVE_OPK",
    "BAD_MESSAGE_VERSION",
    "BAD_MESSAGE_FORMAT",
    "BAD_MESSAGE_MAC",
    "BAD_MESSAGE_SEQUENCE",
    "BAD_MESSAGE_KEY",
    "BAD_SIGN_KEY",
    "BAD_SIGNED_PRE_KEY",
    "BAD_ONE_TIME_PRE_KEY",
    "BAD_MESSAGE_ENCRYPTION",
    "BAD_MESSAGE_DECRYPTION",
    "NOT_ENOUGH_RANDOM",
    "NOT_ENOUGH_MEMORY",
    "NOT_ENOUGH_SPACE"
};

const char *logcode_string(LogCode log_code){
    if (log_code < (sizeof(LOG_CODE_STRINGS)/sizeof(LOG_CODE_STRINGS[0]))) {
        return LOG_CODE_STRINGS[log_code];
    } else {
        return "UNKNOWN_LOG_CODE";
    }
}
