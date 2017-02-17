/*
  Copyright (C) 2017 by Syohei YOSHIDA

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <emacs-module.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

int plugin_is_GPL_compatible;

struct el_cipher {
	EVP_CIPHER_CTX ctx;
	bool is_set_key;
	char *key;
};

struct cipher_names {
	emacs_env *env;
	emacs_value ciphers;
};

static char*
retrieve_string(emacs_env *env, emacs_value str, ptrdiff_t *size)
{
	*size = 0;

	env->copy_string_contents(env, str, NULL, size);
	char *p = malloc(*size);
	if (p == NULL) {
		*size = 0;
		return NULL;
	}
	env->copy_string_contents(env, str, p, size);

	return p;
}

static void
el_cipher_free(void *arg)
{
	struct el_cipher *ec = (struct el_cipher*)arg;
	EVP_CIPHER_CTX_cleanup(&ec->ctx);
	free(ec);
}

static void
add_cipher(const OBJ_NAME *name, void *arg)
{
	struct cipher_names *c = (struct cipher_names*)arg;
	emacs_env *env = c->env;
	emacs_value n = env->make_string(env, name->name, strlen(name->name));

	emacs_value Fcons = env->intern(env, "cons");
	emacs_value args[] = {n, c->ciphers};
	c->ciphers = env->funcall(env, Fcons, 2, args);
}

static emacs_value
Fcipher_init(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct el_cipher *ec = malloc(sizeof(struct el_cipher));
	if (ec == NULL) {
		return env->intern(env, "nil");
	}

	EVP_CIPHER_CTX_init(&ec->ctx);
	ec->is_set_key = false;

	ptrdiff_t size;
	char *cipher_name = retrieve_string(env, args[0], &size);
	if (cipher_name == NULL) {
		return env->intern(env, "nil");
	}

	const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
	if (cipher == NULL) {
		return env->intern(env, "nil");
	}

	int ret = EVP_CipherInit_ex(&ec->ctx, cipher, NULL, NULL, NULL, -1);
	if (ret == 0) {
		return env->intern(env, "nil");
	}

	return env->make_user_ptr(env, el_cipher_free, ec);
}

static emacs_value
Fcipher_generate_random_key(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct el_cipher *ec = env->get_user_ptr(env, args[0]);

	int key_len = EVP_CIPHER_CTX_key_length(&ec->ctx);
	char *key_buf = malloc(key_len+1);
	if (key_buf == NULL) {
		return env->intern(env, "nil");
	}
	RAND_bytes((unsigned char*)key_buf, key_len);

	emacs_value ret = env->make_string(env, key_buf, key_len);
	free(key_buf);
	return ret;
}

static emacs_value
Fcipher_generate_random_iv(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct el_cipher *ec = env->get_user_ptr(env, args[0]);

	int iv_len = EVP_CIPHER_CTX_iv_length(&ec->ctx);
	char *iv_buf = malloc(iv_len+1);
	if (iv_buf == NULL) {
		return env->intern(env, "nil");
	}
	RAND_bytes((unsigned char*)iv_buf, iv_len);

	emacs_value ret = env->make_string(env, iv_buf, iv_len);
	free(iv_buf);
	return ret;
}

static emacs_value
Fcipher_set_key(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct el_cipher *ec = env->get_user_ptr(env, args[0]);

	ptrdiff_t size;
	char *key = retrieve_string(env, args[1], &size);
	if (key == NULL) {
		return env->intern(env, "nil");
	}

	int key_len = EVP_CIPHER_CTX_key_length(&ec->ctx);
	if ((size - 1) != key_len) {
		free(key);
		return env->intern(env, "nil");
	}

	int ret = EVP_CipherInit_ex(&ec->ctx, NULL, NULL, (const unsigned char*)key, NULL, -1);
	free(key);
	if (ret == 0) {
		return env->intern(env, "nil");
	}

	ec->is_set_key = true;
	return env->intern(env, "t");
}

static emacs_value
Fcipher_set_iv(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct el_cipher *ec = env->get_user_ptr(env, args[0]);

	ptrdiff_t size;
	char *iv = retrieve_string(env, args[1], &size);
	if (iv == NULL) {
		return env->intern(env, "nil");
	}

	int iv_len = EVP_CIPHER_CTX_iv_length(&ec->ctx);
	if ((size - 1) != iv_len) {
		free(iv);
		return env->intern(env, "nil");
	}

	int ret = EVP_CipherInit_ex(&ec->ctx, NULL, NULL, NULL, (const unsigned char*)iv, -1);
	free(iv);
	if (ret == 0) {
		return env->intern(env, "nil");
	}

	return env->intern(env, "t");
}

static emacs_value
Fciphers(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
	struct cipher_names cn = {env, env->intern(env, "nil") };
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, add_cipher, (void*)&cn);

	emacs_value Freverse = env->intern(env, "reverse");
	emacs_value rev_args[] = {cn.ciphers};

	return env->funcall(env, Freverse, 1, rev_args);
}

static void
bind_function(emacs_env *env, const char *name, emacs_value Sfun)
{
	emacs_value Qfset = env->intern(env, "fset");
	emacs_value Qsym = env->intern(env, name);
	emacs_value args[] = { Qsym, Sfun };

	env->funcall(env, Qfset, 2, args);
}

static void
provide(emacs_env *env, const char *feature)
{
	emacs_value Qfeat = env->intern(env, feature);
	emacs_value Qprovide = env->intern (env, "provide");
	emacs_value args[] = { Qfeat };

	env->funcall(env, Qprovide, 1, args);
}

int
emacs_module_init(struct emacs_runtime *ert)
{
	emacs_env *env = ert->get_environment(ert);

	OpenSSL_add_all_algorithms();

#define DEFUN(lsym, csym, amin, amax, doc, data) \
	bind_function (env, lsym, env->make_function(env, amin, amax, csym, doc, data))

	DEFUN("cipher-core-ciphers", Fciphers, 0, 0, NULL, NULL);
	DEFUN("cipher-core-init", Fcipher_init, 1, 1, NULL, NULL);
	DEFUN("cipher-core-set-key", Fcipher_set_key, 2, 2, NULL, NULL);
	DEFUN("cipher-core-set-cipher", Fcipher_set_iv, 2, 2, NULL, NULL);

	DEFUN("cipher-core-generate-random-key", Fcipher_generate_random_key,
	      1, 1, NULL, NULL);
	DEFUN("cipher-core-generate-random-iv", Fcipher_generate_random_iv,
	      1, 1, NULL, NULL);

#undef DEFUN

	provide(env, "cipher-core");
	return 0;
}

/*
  Local Variables:
  c-basic-offset: 8
  indent-tabs-mode: t
  End:
*/
