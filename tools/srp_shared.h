#include <stddef.h>
#include <stdbool.h>

void user_verifier_lookup(char * username,
							size_t *verifier_len, char **verifier,
							size_t *salt_len, char **salt,
							bool *use_default_2048_bit_n_modulus,
							char **n_modulus_ascii,
							char **generator_ascii,
							void *user_data);
