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
  const std::string &output)
{
  const gchar *reason;
  GString *decoded = g_string_new("");
  if (http_string_assign_form_url_decode(decoded, TRUE, input.c_str(), input.length(), &reason))
    {
      BOOST_REQUIRE_MESSAGE(output == decoded->str,
                            TEST_ID "return missmatch: '"
                            << output << "' != '" << decoded->str << "'");
    }
  g_string_free(decoded, TRUE);
}

struct test
{
  const std::string input;
  const std::string output;
};

std::vector<struct test> test_table =
{
  { "12+3",   "12 3"},
  { "xy%20z", "xy z"},
  { "ab c",   "ab c"},  // not a valid form URL encoded input
  { "%E8%B6%85%E6%96%87%E6%9C%AC%C3%8D%C3%96%C3%9C%C3%93%D0%90%D0%91%D0%92%D0%93%D0%94%C4%91%C3%A4%3C%3E%23%26%40%40",
              "超文本ÍÖÜÓАБВГДđä<>#&@@"},
};

BOOST_AUTO_TEST_CASE(http_parse_query_string)
{
  for (unsigned i = 0; i < test_table.size(); i++)
    {
      test_case(i, test_table[i].input, test_table[i].output);
    }
}
