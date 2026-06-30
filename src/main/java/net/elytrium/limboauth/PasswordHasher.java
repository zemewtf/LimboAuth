/*
 * Copyright (C) 2021 - 2025 Elytrium
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.elytrium.limboauth;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;

public final class PasswordHasher {

  private PasswordHasher() {
    throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
  }

  public static String hash(String password) {
    if (password == null) {
      throw new IllegalArgumentException("Password cannot be null");
    }

    int memory = Settings.IMP.MAIN != null ? Settings.IMP.MAIN.ARGON2_MEMORY : 16384;
    int iterations = Settings.IMP.MAIN != null ? Settings.IMP.MAIN.ARGON2_ITERATIONS : 3;
    int parallelism = Settings.IMP.MAIN != null ? Settings.IMP.MAIN.ARGON2_PARALLELISM : 2;

    Argon2Function argon2 = Argon2Function.getInstance(
        memory,
        iterations,
        parallelism,
        32,
        Argon2.ID
    );

    return Password.hash(password).addRandomSalt(16).with(argon2).getResult();
  }

  public static boolean verify(String password, String hash) {
    if (password == null || hash == null) {
      return false;
    }

    if (hash.startsWith("$argon2id$") || hash.startsWith("$argon2i$") || hash.startsWith("$argon2d$")) {
      try {
        String[] parts = hash.split("\\$");
        if (parts.length >= 6) {
          int memory = 16384;
          int iterations = 3;
          int parallelism = 2;

          String[] params = parts[3].split(",");
          for (String param : params) {
            if (param.startsWith("m=")) {
              memory = Integer.parseInt(param.substring(2));
            } else if (param.startsWith("t=")) {
              iterations = Integer.parseInt(param.substring(2));
            } else if (param.startsWith("p=")) {
              parallelism = Integer.parseInt(param.substring(2));
            }
          }

          String hashPart = parts[5];
          int remainder = hashPart.length() % 4;
          if (remainder == 2) {
            hashPart += "==";
          } else if (remainder == 3) {
            hashPart += "=";
          }
          byte[] decodedHash = java.util.Base64.getDecoder().decode(hashPart);
          int hashLength = decodedHash.length;

          Argon2 variant = Argon2.ID;
          if (parts[1].equals("argon2i")) {
            variant = Argon2.I;
          } else if (parts[1].equals("argon2d")) {
            variant = Argon2.D;
          }

          Argon2Function argon2 = Argon2Function.getInstance(
              memory,
              iterations,
              parallelism,
              hashLength,
              variant
          );
          return Password.check(password, hash).with(argon2);
        }
      } catch (Exception ignored) {
        // fallback
      }
      try {
        return Password.check(password, hash).withArgon2();
      } catch (Exception e) {
        return false;
      }
    }

    String bcryptHash = hash;
    if (hash.startsWith("BCRYPT$")) {
      bcryptHash = hash.replace("BCRYPT$", "$2a$");
    }

    if (bcryptHash.startsWith("$2a$") || bcryptHash.startsWith("$2b$") || bcryptHash.startsWith("$2y$")) {
      try {
        return Password.check(password, bcryptHash).withBcrypt();
      } catch (Exception e) {
        return false;
      }
    }

    return false;
  }
}
