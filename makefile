#
# makefile
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Note - Shell commands must start with a tab character at the beginning
# of each line NOT spaces..!
#
#  30 Jul 23   0.1   - Initial version - MT
#   4 Aug 23         - Added backup files to tar archive - MT
#  11 Nov 24   0.2   - Project name derived from current folder - MT
#  24 Sep 25   0.3   - Added ability to include common files - MT
#  14 Jan 26   0.4   - Disable built-in suffix rules - MT
#  02 Sep 26   0.5   - Separated DEBUG and VERBOSE - MT
#                    - Removed list option - MT
#                    - Common modules are now recompiled automatically when
#                      needed as any program now depends on 'common', which
#                      in turn is dependent on the common object files - MT
#                    - Now passes COMMIT_ID to programs - MT
#

PROJECT	=  $(strip $(notdir $(abspath $(CURDIR)/.)))

COMMON	=  
#SOURCE	=  $(wildcard *.c)  # Compile all source files
SOURCE	=  $(filter-out $(COMMON:=.c), $(wildcard *.c))  # Compile all source files other than common files
INCLUDE	=  $(wildcard *.h)  # Automatically get all include files
BACKUP	=  $(wildcard *.c.[0-9])
OBJECT	=  $(SOURCE:.c=.o)
PROGRAM	=  $(SOURCE:.c=)

FILES	=  $(SOURCE) $(COMMON) $(BACKUP) $(INCLUDE) LICENSE makefile makefile.linux makefile.osf1 README.md # .gitignore .gitattributes
LANG	=  LANG_$(shell (echo $$LANG | cut -f 1 -d '_'))
UNAME	=  $(shell uname)
BRANCH	=  $(shell git rev-parse --abbrev-ref HEAD > /dev/null 2>&1 && echo `git rev-parse --abbrev-ref HEAD 2>/dev/null`- || true)

LIBS	=
FLAGS	=  -fcommon -Wall -pedantic -std=gnu89
FLAGS	+= -Wno-comment -Wno-unused-function #-Wno-deprecated-declarations -Wno-builtin-macro-redefined
FLAGS	+= -D $(LANG)

# Define the current commit and pass to the compiler - returns an empty string if git not installed
COMPILER=  `$(CC) -v 2>&1 | grep ' version ' | sed -e 's/([^()]*)//g; s/version//g; s/  */ /g; y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/; s/[ 	]*$$//' | sed -n '1p'`
COMMIT	=  $(shell command -v git >/dev/null 2>&1 && git log -1 HEAD --format=%h 2>/dev/null)
FLAGS	+= $(shell if [ -n "$(COMMIT)" ]; then echo "-DCOMMIT_ID='\"[Commit Id : $(COMMIT)]\"'"; fi)
FLAGS	+= $(shell if [ -n "$(COMPILER)" ]; then echo "-D__compiler__='\"$(COMPILER)\"'"; fi)

ifdef DEBUG
FLAGS	+=  -g
else
FLAGS	+=  -O2
endif

.SUFFIXES:  # Disable built-in suffix rules (required for older version of make)

default:$(PROGRAM) # $(OBJECT)

all:clean $(PROGRAM) $(OBJECT)

common:$(COMMON:=.o)  # Compiles common modules (using rules below)

$(PROGRAM):common  # All programs depend on the common modules 

%.o: %.c  # Compile other  sources (won't include common - already compiled)
ifdef VERBOSE
	@echo "Compile : " $(CC) $(FLAGS) -c $<
endif
	@$(CC) $(FLAGS) -c $<

%: %.o  # Link and display executable file name to indecate progress
ifdef VERBOSE
	@echo "Link :     "$(CC) $(FLAGS) $(COMMON:=.o) -o $@ $<  $(LIBS)
endif
	@$(CC) $(FLAGS) $(COMMON:=.o) -o $@ $< $(LIBS)
	@ls --color $@

clean:
ifdef VERBOSE
	@rm -f $(COMMON:=.o) -v  2>&1 | sed 's/removed/Delete :  /g' | sed 's/'\''//g'
	@rm -f $(OBJECT) -v  2>&1 | sed 's/removed/Delete :  /g' | sed 's/'\''//g'
	@rm -f $(PROGRAM) -v 2>&1 | sed 's/removed/Delete :  /g' | sed 's/'\''//g'
else
	@rm -f $(COMMON:=.o) # -v
	@rm -f $(OBJECT) # -v
	@rm -f $(PROGRAM) # -v
endif

backup: clean
ifdef VERBOSE
		@tar -cvpf ..\/$(PROJECT)-$(BRANCH)`date +'%Y%m%d%H%M'`.tar $(FILES);cd .. && ls --color $(PROJECT)-$(BRANCH)`date +'%Y%m%d%H%M'`.tar
else
		@tar -cpf ..\/$(PROJECT)-$(BRANCH)`date +'%Y%m%d%H%M'`.tar $(FILES);cd .. && ls --color $(PROJECT)-$(BRANCH)`date +'%Y%m%d%H%M'`.tar
endif
