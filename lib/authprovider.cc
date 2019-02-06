/***************************************************************************
 *
 * Copyright (c) 2000-2015 BalaBit IT Ltd, Budapest, Hungary
 * Copyright (c) 2015-2018 BalaSys IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 ***************************************************************************/

#include <zorp/authprovider.h>
#include <zorpll/log.h>


/**
 * z_auth_provider_check_passwd:
 *
 * NOTE: this function requires the Python lock to be held.
 **/
gboolean
z_auth_provider_check_passwd(ZAuthProvider * /* self */,
                             gchar * /* session_id */,
                             gchar * /* username */,
                             const gchar * /* passwd */,
                             gchar *** /* groups */,
                             ZProxy * /* proxy */)
{
  return FALSE;
}
