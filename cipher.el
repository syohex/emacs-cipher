;;; cipher.el --- OpenSSL cipher binding -*- lexical-binding: t; -*-

;; Copyright (C) 2017 by Syohei YOSHIDA

;; Author: Syohei YOSHIDA <syohex@gmail.com>
;; URL: https://github.com/syohex/
;; Version: 0.01
;; Package-Requires: ((emacs "25"))

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;;; Code:

(require 'cipher-core)

(defun cipher-ciphers ()
  (cipher-core-ciphers))

(defun cipher-init (cipher)
  (cipher-core-init cipher))

(defun cipher-generate-random-key (context)
  (cipher-core-generate-random-key context))

(defun cipher-generate-random-iv (context)
  (cipher-core-generate-random-iv context))

(provide 'cipher)

;;; cipher.el ends here
