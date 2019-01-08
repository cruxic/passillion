#https://superuser.com/questions/137957/how-to-convert-aspell-dictionary-to-simple-list-of-words
aspell -d en dump master | aspell -l en expand > my.dict
