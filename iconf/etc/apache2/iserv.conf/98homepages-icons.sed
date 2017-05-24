/^# Benutzer-Homepages/a\
  # Catch apache default icons\
  \<Location \/icons\>\
     Options +FollowSymlinks\
     RewriteRule ^\/icons\/(.*) \/usr\/share\/apache2\/icons\/\$1 [END]\
  \<\/Location\>\
  \<Directory \/usr\/share\/apache2\/icons\/>\
     Allow from all\
  \<\/Directory\>\
