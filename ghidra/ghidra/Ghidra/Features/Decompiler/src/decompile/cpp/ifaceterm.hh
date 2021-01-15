/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Add some terminal capabilities to the command-line interface
#include "interface.hh"

#ifdef __TERMINAL__
extern "C" {
#include <termios.h>
#include <errno.h>
}
#endif

class IfaceTerm : public IfaceStatus {
#ifdef __TERMINAL__
  bool is_terminal;		// True if the input stream is a terminal
  int4 ifd;			// Underlying file descriptor
  struct termios itty;		// Original terminal settings
#endif
  int4 doCompletion(string &line,int4 cursor);
  virtual void readLine(string &line);
public:
  IfaceTerm(const string &prmpt,istream &is,ostream &os);
  virtual ~IfaceTerm(void);
};
