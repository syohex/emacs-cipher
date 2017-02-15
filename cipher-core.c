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

int plugin_is_GPL_compatible;

struct cipher_names {
	emacs_env *env;
	emacs_value ciphers;
};

static void add_cipher(const OBJ_NAME *name, void *arg)
{
	struct cipher_names *c = (struct cipher_names*)arg;
	emacs_env *env = c->env;
	emacs_value n = env->make_string(env, name->name, strlen(name->name));

	emacs_value Fcons = env->intern(env, "cons");
	emacs_value args[] = {n, c->ciphers};
	c->ciphers = env->funcall(env, Fcons, 2, args);
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
