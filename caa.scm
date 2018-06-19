(use femto.dns)

(let1 response (dns-query "google.com" :type "caa")
  (answers response))
