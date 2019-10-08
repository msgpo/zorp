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
 ***************************************************************************/

#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>

#include <vector>

#include "../http.h"

#define TEST_ID "id=" << id << ", "

void
test_case(
  const unsigned id,
  const std::string &input,
  const std::string &key,
  const std::string &value,
  const bool &found)
{
  std::string found_value;

  bool res = http_query_string_get_value(input, key, found_value);

  BOOST_REQUIRE_MESSAGE(res == found,
                        TEST_ID "return missmatch: '"
                        << res << "' != '" << found << "'");
  BOOST_REQUIRE_MESSAGE(found_value == value,
                        TEST_ID "found value but it does not match expected one: '"
                        << found_value << "' != '" << value << "'");
}

struct test
{
  const std::string input;
  const std::string key;
  const std::string value;
  const bool found;
};

std::vector<struct test> test_table =
{
  { "a=123&b=xyz&c=abc",      "a", "123", true},
  { "a=123&b=xyz&c=abc",      "b", "xyz", true},
  { "a=123&b=xyz&c=abc",      "c", "abc", true},
  { "a=123",                  "a", "123", true},
  { "a=",                     "a", "",    true},
  { "a=123&b=",               "b", "",    true},
  { "a=123&b&c=abc",          "b", "",    false},
  { "a=123&b",                "b", "",    false},
  { "a=123&",                 "b", "",    false},
  { "ca=123",                 "c", "",    false},
  { "ca=123",                 "a", "",    false},
  { "ca=123&a=xyz",           "a", "xyz", true},
};

BOOST_AUTO_TEST_CASE(http_parse_query_string)
{
  for (unsigned i = 0; i < test_table.size(); i++)
    {
      test_case(i, test_table[i].input, test_table[i].key,
                   test_table[i].value, test_table[i].found);
    }
}
