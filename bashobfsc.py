#!/bin/env python3
import sys
# import re
# This file are combination from other project like https://gist.github.com/dimasma0305/c3d5d3cac71c8240a491a3010f2372b8
# and https://github.com/precious/bash_minifier
NUMLIST = {
    "\\": "\\\\",
    "0": "${#}",
    "1": "${##}",
    "2": "$((${##}<<$((${##}))))",
    "3": "$((${##}<<$((${##}))^${##}))",
    "4": "$((${##}<<$((${##}))<<$((${##}))))",
    "5": "$((${##}<<$((${##}))<<$((${##}))^${##}))",
    "6": "$(($((${##}<<$((${##}))^${##}))<<${##}))",
    "7": "$(($((${##}<<$((${##}))^${##}))<<${##}^${##}))",
    "8": "$((${##}<<$((${##}))<<$((${##}))<<$((${##}))))",
    "9": "$((${##}<<$((${##}))<<$((${##}))<<$((${##}))^${##}))",
}

BASHSPECIALCHARS = {
    b'': 40, b'\x01': 1, b'\x02': 2, b'\x03': 3, b'\x04': 4, b'\x05': 5, b'\x06': 6, b'\x07': 7, b'\\8': 8, b'\\9': 9, b'\x08': 10, b'\x0e': 16, b'\x0f': 17, b'\x018': 18, b'\x019': 19, b'\x10': 20, b'\x11': 21, b'\x12': 22, b'\x13': 23, b'\x14': 24, b'\x15': 25, b'\x16': 26, b'\x17': 27, b'\x028': 28, b'\x029': 29, b'\x18': 30, b'\x19': 31, b'\x1a': 32, b'\x1b': 33, b'\x1c': 34, b'\x1d': 35, b'\x1e': 36, b'\x1f': 37, b'\x038': 38, b'\x039': 39, b'!': 41, b'"': 42, b'#': 43, b'$': 44, b'%': 45, b'&': 46, b"'": 47, b'\x048': 48, b'\x049': 49, b'(': 50, b')': 51, b'*': 52, b'+': 53, b',': 54, b'-': 55, b'.': 56, b'/': 57, b'\x058': 58, b'\x059': 59, b'0': 60, b'1': 61, b'2': 62, b'3': 63, b'4': 64, b'5': 65, b'6': 66, b'7': 67, b'\x068': 68, b'\x069': 69, b'8': 158, b'9': 159, b':': 72, b';': 73, b'<': 74, b'=': 75, b'>': 76, b'?': 77, b'\x078': 78, b'\x079': 79, b'\\80': 80, b'\\81': 81, b'\\82': 82, b'\\83': 83, b'\\84': 84, b'\\85': 85, b'\\86': 86, b'\\87': 87, b'\\88': 88, b'\\89': 89, b'\\90': 90, b'\\91': 91, b'\\92': 92, b'\\93': 93, b'\\94': 94, b'\\95': 95, b'\\96': 96, b'\\97': 97, b'\\98': 98, b'\\99': 99, b'@': 100, b'A': 101, b'B': 102, b'C': 103, b'D': 104, b'E': 105, b'F': 106, b'G': 107, b'\x088': 108, b'\x089': 109, b'H': 110, b'I': 111, b'J': 112, b'K': 113, b'L': 114, b'M': 115, b'N': 116, b'O': 117, b'P': 120, b'Q': 121, b'R': 122, b'S': 123, b'T': 124, b'U': 125, b'V': 126, b'W': 127, b'X': 130, b'Y': 131, b'Z': 132, b'[': 133, b'\\': 134, b']': 135, b'^': 136, b'_': 137, b'`': 140, b'a': 141, b'b': 142, b'c': 143, b'd': 144, b'e': 145, b'f': 146, b'g': 147, b'h': 150, b'i': 151, b'j': 152, b'k': 153, b'l': 154, b'm': 155, b'n': 156, b'o': 157, b'p': 160, b'q': 161, b'r': 162, b's': 163, b't': 164, b'u': 165, b'v': 166, b'w': 167, b'\x0e8': 168, b'\x0e9': 169, b'x': 170, b'y': 171, b'z': 172, b'{': 173, b'|': 174, b'}': 175, b'~': 176, b'\x7f': 177, b'\x0f8': 178, b'\x0f9': 179, b'\x0180': 180, b'\x0181': 181, b'\x0182': 182, b'\x0183': 183, b'\x0184': 184, b'\x0185': 185, b'\x0186': 186, b'\x0187': 187, b'\x0188': 188, b'\x0189': 189, b'\x0190': 190, b'\x0191': 191, b'\x0192': 192, b'\x0193': 193, b'\x0194': 194, b'\x0195': 195, b'\x0196': 196, b'\x0197': 197, b'\x0198': 198, b'\x0199': 199, b'\x80': 200, b'\x81': 201, b'\x82': 202, b'\x83': 203, b'\x84': 204, b'\x85': 205, b'\x86': 206, b'\x87': 207, b'\x108': 208, b'\x109': 209, b'\x88': 210, b'\x89': 211, b'\x8a': 212, b'\x8b': 213, b'\x8c': 214, b'\x8d': 215, b'\x8e': 216, b'\x8f': 217, b'\x118': 218, b'\x119': 219, b'\x90': 220, b'\x91': 221, b'\x92': 222, b'\x93': 223, b'\x94': 224, b'\x95': 225, b'\x96': 226, b'\x97': 227, b'\x128': 228, b'\x129': 229, b'\x98': 230, b'\x99': 231, b'\x9a': 232, b'\x9b': 233, b'\x9c': 234, b'\x9d': 235, b'\x9e': 236, b'\x9f': 237, b'\x138': 238, b'\x139': 239, b'\xa0': 240, b'\xa1': 241, b'\xa2': 242, b'\xa3': 243, b'\xa4': 244, b'\xa5': 245, b'\xa6': 246, b'\xa7': 247, b'\x148': 248, b'\x149': 249, b'\xa8': 250, b'\xa9': 251, b'\xaa': 252, b'\xab': 253, b'\xac': 254
}

LITERALS = ["{", "}", ",", ">", "<", "<<", ">>", "<<<", ">>>",
            "$", "'", '"', "`", "(", ")", "&", "&&", "#", "!", "|", ";"]
DELIMITER_NO_SPACE = [">", "<", "<<", ">>", "<<<", ">>>", "&", "&&", "!", "|"]

class ParseBash:
    def toBashEscape(self, cmd):
        result = ""
        for mystring in cmd:
            result += f"\\{BASHSPECIALCHARS[bytes(mystring, 'utf-8')]}"
        return result

    def transform(self, cmd):
        result = ""
        for mystring in cmd:
            if mystring in NUMLIST.keys():
                result += NUMLIST[mystring]
            else:
                result += mystring
        return result
    # def nospace(self, cmd)
    #     for word in DELIMITER_NO_SPACE:
    #         worlds = words.replace(" "+word+" ", word)

    def parse(self, cmd):
        '''
        example input { arg1 , arg2 , arg3 }
        '''
        text: str = cmd
        deob_cmd = ""
        for word in text.split():
            if word in LITERALS:
                deob_cmd += word
            else:
                tmp = self.toBashEscape(word)
                tmp = self.transform(tmp)
                tmp = r"$\'%s\'" % tmp
                deob_cmd += tmp
        return deob_cmd

class BashFileIterator:
    class _Delimiter(object):
        def __init__(self, character, _type=''):
            self.character = character
            # type may be 'AP' or 'AS' (Arithmetic Expansion delimited by (()) or [] respectively),
            #             'S' (Command Substitution) or 'P' (Parameter Expansion)
            # type is set only for parenthesis or curly brace and square brace that opens group
            # e.g. in this statement $((1+2)) only the 1st '(' will have type ('AP')
            self.type = _type

        def is_group_opening(self):
            return bool(self.type or self.character in ("'", '"', '`'))

        def __eq__(self, other):
            if isinstance(other, BashFileIterator._Delimiter):
                return other.character == self.character
            if isinstance(other, str):
                return other == self.character
            return False

        def __ne__(self, other):
            return not self.__eq__(other)

        def __str__(self):
            return self.character

        __repr__ = __str__

    def __init__(self, src):
        self.src = src
        self.reset()

    def reset(self):
        self.pos = 0
        self.insideComment = False
        self.insideHereDoc = False

        # possible characters in stack:
        # (, ) -- means Arithmetic Expansion or Command Substitution
        # {, } -- means Parameter Expansion
        # [, ] -- means Arithmetic Expansion
        # ` -- means Command Substitution
        # ' -- means single-quoted string
        # " -- means double-quoted string
        self._delimiters_stack = []
        self._indices_of_escaped_characters = set()

    def getLastGroupOpeningDelimiter(self):
        return next((d for d in reversed(self._delimiters_stack) if d.is_group_opening()),
                    BashFileIterator._Delimiter(''))

    def pushDelimiter(self, character, _type=''):
        d = BashFileIterator._Delimiter(character, _type=_type)
        last_opening = self.getLastGroupOpeningDelimiter()
        last = self._delimiters_stack[-1] if len(self._delimiters_stack) > 0 else BashFileIterator._Delimiter('')

        if d in ('{', '}'):
            if _type != '':  # delimiter that opens group
                self._delimiters_stack.append(d)
            elif d == '}' and last == '{':
                self._delimiters_stack.pop()
        elif d in ('(', ')'):
            if _type != '':  # delimiter that opens group
                self._delimiters_stack.append(d)
            elif last_opening == '(':
                if last == '(' and d == ')':
                    self._delimiters_stack.pop()
                else:
                    self._delimiters_stack.append(d)
        elif d in ('[', ']'):
            if _type != '':  # delimiter that opens group
                self._delimiters_stack.append(d)
            elif last_opening == '[':
                if last == '[' and d == ']':
                    self._delimiters_stack.pop()
                else:
                    self._delimiters_stack.append(d)
        elif d == "'" and last_opening != '"' or d == '"' and last_opening != "'" or d == '`':
            if d == last_opening:
                self._delimiters_stack.pop()
            else:
                self._delimiters_stack.append(d)

    def isInsideGroup(self):
        return len(self._delimiters_stack) != 0

    def getPreviousCharacters(self, n, should_not_start_with_escaped=True):
        """
        'should_not_start_with_escaped' means return empty string if the first character is escaped 
        """
        first_character_index = max(0, self.pos - n)
        if first_character_index in self._indices_of_escaped_characters:
            return ''
        else:
            return self.src[max(0, self.pos - n):self.pos]

    def getPreviousCharacter(self, should_not_start_with_escaped=True):
        return self.getPreviousCharacters(1, should_not_start_with_escaped=should_not_start_with_escaped)

    def getNextCharacters(self, n):
        return self.src[self.pos + 1:self.pos + n + 1]

    def getNextCharacter(self):
        return self.getNextCharacters(1)

    def getPreviousWord(self):
        word = ''
        i = 1
        while i <= self.pos:
            newWord = self.getPreviousCharacters(i)
            if not newWord.isalpha():
                break
            word = newWord
            i += 1
        return word

    def getNextWord(self):
        word = ''
        i = 1
        while self.pos + i < len(self.src):
            newWord = self.getNextCharacters(i)
            if not newWord.isalpha():
                break
            word = newWord
            i += 1
        return word

    def getPartOfLineAfterPos(self, skip=0):
        result = ''
        i = self.pos + 1 + skip
        while i < len(self.src) and self.src[i] != '\n':
            result += self.src[i]
            i += 1
        return result

    def getPartOfLineBeforePos(self, skip=0):
        result = ''
        i = self.pos - 1 - skip
        while i >= 0 and self.src[i] != '\n':
            result = self.src[i] + result
            i -= 1
        return result

    def charactersGenerator(self):
        hereDocWord = ''
        _yieldNextNCharactersAsIs = 0

        def close_heredoc():
            self.insideHereDoc = False

        callbacks_after_yield = []

        while self.pos < len(self.src):
            ch = self.src[self.pos]

            if _yieldNextNCharactersAsIs > 0:
                _yieldNextNCharactersAsIs -= 1
            elif ch == "\\" and not self.isEscaped():
                self._indices_of_escaped_characters.add(self.pos + 1)
            else:
                if ch == "\n" and not self.isInsideSingleQuotedString() and not self.isInsideDoubleQuotedString():
                    # handle end of comments and heredocs
                    if self.insideComment:
                        self.insideComment = False
                    elif self.insideHereDoc and self.getPartOfLineBeforePos() == hereDocWord:
                        callbacks_after_yield.append(close_heredoc)
                elif not self.isInsideComment() and not self.isInsideHereDoc():
                    if ch in ('"', "'"):
                        # single quote can't be escaped inside single-quoted string
                        if not self.isEscaped() or ch == "'" and self.isInsideSingleQuotedString():
                            self.pushDelimiter(ch)
                    elif not self.isInsideSingleQuotedString():
                        if not self.isEscaped():
                            if ch == "#" and not self.isInsideGroup() and \
                                    (self.getPreviousCharacter() in ('\n', '\t', ' ', ';') or self.pos == 0):
                                # handle comments
                                self.insideComment = True
                            elif ch == '`':
                                self.pushDelimiter(ch)
                            elif ch == '$':
                                next_char = self.getNextCharacter()
                                if next_char in ('{', '(', '['):
                                    next_2_chars = self.getNextCharacters(2)
                                    _type = 'AP' if next_2_chars == '((' else {'{': 'P', '(': 'S', '[': 'AS'}[next_char]
                                    self.pushDelimiter(next_char, _type=_type)
                                    _yieldNextNCharactersAsIs = 1
                            elif ch in ('{', '}', '(', ')', '[', ']'):
                                self.pushDelimiter(ch)
                            elif ch == '<' and self.getNextCharacter() == '<' and not self.isInsideGroup():
                                _yieldNextNCharactersAsIs = 1

                                # we should handle correctly heredocs and herestrings like this one:
                                # echo <<< one

                                if self.getNextCharacters(2) != '<<':
                                    # heredoc
                                    self.insideHereDoc = True
                                    hereDocWord = self.getPartOfLineAfterPos(skip=1)
                                    if hereDocWord[0] == '-':
                                        hereDocWord = hereDocWord[1:]
                                    hereDocWord = hereDocWord.strip().replace('"', '').replace("'", '')

            yield ch

            while len(callbacks_after_yield) > 0:
                callbacks_after_yield.pop()()

            self.pos += 1

        assert not self.isInsideGroup(), 'Invalid syntax'


    def isEscaped(self):
        return self.pos in self._indices_of_escaped_characters

    def isInsideDoubleQuotedString(self):
        return self.getLastGroupOpeningDelimiter() == '"'

    def isInsideSingleQuotedString(self):
        return self.getLastGroupOpeningDelimiter() == "'"

    def isInsideComment(self):
        return self.insideComment

    def isInsideHereDoc(self):
        return self.insideHereDoc

    def isInsideParameterExpansion(self):
        return self.getLastGroupOpeningDelimiter() == '{'

    def isInsideArithmeticExpansion(self):
        return self.getLastGroupOpeningDelimiter().type in ('AP', 'AS')

    def isInsideCommandSubstitution(self):
        last_opening_delimiter = self.getLastGroupOpeningDelimiter()
        return last_opening_delimiter == '`' or last_opening_delimiter.type == 'S'

    def isInsideAnything(self):
        return self.isInsideGroup() or self.insideHereDoc or self.insideComment

    def isInsideGroupWhereWhitespacesCannotBeTruncated(self):
        return self.isInsideComment() or self.isInsideDoubleQuotedString() or self.isInsideDoubleQuotedString() or \
               self.isInsideHereDoc() or self.isInsideParameterExpansion()


def minify(src):
    # first: remove all comments
    it = BashFileIterator(src)
    src = ""  # result
    for ch in it.charactersGenerator():
        if not it.isInsideComment():
            src += ch

    # secondly: remove empty strings, strip lines and truncate spaces (replace groups of whitespaces by single space)
    it = BashFileIterator(src)
    src = ""  # result
    emptyLine = True  # means that no characters has been printed in current line so far
    previousSpacePrinted = True
    for ch in it.charactersGenerator():
        if it.isInsideSingleQuotedString():
            # first of all check single quoted string because line continuation does not work inside
            src += ch
        elif ch == "\\" and not it.isEscaped() and it.getNextCharacter() == "\n":
            # then check line continuation
            # line continuation will occur on the next iteration. just skip this backslash
            continue
        elif ch == "\n" and it.isEscaped():
            # line continuation occurred
            # backslash at the very end of line means line continuation
            # so remove previous backslash and skip current newline character ch
            continue
        elif it.isInsideGroupWhereWhitespacesCannotBeTruncated() or it.isEscaped():
            src += ch
        elif ch in (' ', '\t') and not previousSpacePrinted and not emptyLine and \
                not it.getNextCharacter() in (' ', '\t', '\n'):
            src += " "
            previousSpacePrinted = True
        elif ch == "\n" and it.getPreviousCharacter() != "\n" and not emptyLine:
            src += ch
            previousSpacePrinted = True
            emptyLine = True
        elif ch not in (' ', '\t', '\n'):
            src += ch
            previousSpacePrinted = False
            emptyLine = False

    # thirdly: get rid of newlines
    it = BashFileIterator(src)
    src = ""  # result
    for ch in it.charactersGenerator():
        if it.isInsideAnything() or ch != "\n":
            src += ch
        else:
            prevWord = it.getPreviousWord()
            nextWord = it.getNextWord()
            if it.getNextCharacter() == '{':  # functions declaration, see test t8.sh
                if it.getPreviousCharacter() == ')':
                    continue
                else:
                    src += ' '
            elif prevWord in ("until", "while", "then", "do", "else", "in", "elif", "if") or \
                            nextWord in ("in",) or \
                            it.getPreviousCharacter() in ("{", "(") or \
                            it.getPreviousCharacters(2) in ("&&", "||"):
                src += " "
            elif nextWord in ("esac",) and it.getPreviousCharacters(2) != ';;':
                if it.getPreviousCharacter() == ';':
                    src += ';'
                else:
                    src += ';;'
            elif it.getNextCharacter() != "" and it.getPreviousCharacter() not in (";", '|'):
                src += ";"

    # finally: remove spaces around semicolons and pipes and other delimiters
    it = BashFileIterator(src)
    src = ""  # result
    other_delimiters = DELIMITER_NO_SPACE #('|', '&', ';', '<', '>', '(', ')')  # characters that may not be surrounded by whitespaces
    for ch in it.charactersGenerator():
        if it.isInsideGroupWhereWhitespacesCannotBeTruncated():
            src += ch
        elif ch in (' ', '\t') \
                and (it.getPreviousCharacter() in other_delimiters or
                             it.getNextCharacter() in other_delimiters) \
                and it.getNextCharacters(2) not in ('<(', '>('):  # process substitution
                                                                    # see test t_process_substitution.sh for details
            continue
        else:
            src += ch

    return src


##if __name__ == "__main__":
##    # https://www.gnu.org/software/bash/manual/html_node/Reserved-Word-Index.html
##    # http://pubs.opengroup.org/onlinepubs/009695399/utilities/xcu_chap02.html
##    # http://pubs.opengroup.org/onlinepubs/9699919799/
##
##    # get bash source from file or from stdin
##    src = ""
##    if len(sys.argv) > 1:
##        with open(sys.argv[1], "r") as ifile:
##            src = ifile.read()
##    else:
##        src = sys.stdin.read()
##    # use stdout.write instead of print to avoid newline at the end (print with comma at the end does not work)
##    sys.stdout.write(minify(src))

def obfuscate(txt: str):
    txt = txt.replace(';', ' ; ')
    words = txt.split(" ")
    temp = []
    parsed = ""
    for i, word in enumerate(words):
        if word not in LITERALS:
            temp.append(word)
            if i == len(words) - 1:
                wjoin = " , ".join(temp)+" , "
                parsed += ParseBash().parse("{ "+wjoin+" }")
                temp = []
            continue
        wjoin = " , ".join(temp)+" , "
        parsed += ParseBash().parse("{ "+wjoin+" }")
        parsed += word
        temp = []
    return parsed


if __name__ == "__main__":
    try:
        # arg1 = sys.argv[1]
        src = ""
        if len(sys.argv) > 1:
            with open(sys.argv[1], "r") as ifile:
                src = ifile.read()
        else:
            src = sys.stdin.read()
        #print(src)
        minified = minify(src)
        #print(minified)
        txt_obfuscated = obfuscate(minified)
        sys.stdout.write("${!#}<<<" + txt_obfuscated)
    except Exception as e:
        print(e)
        print("Usage: python3 Bash_Obfuscation.py <File Name>")