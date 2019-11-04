/*
 * Copyright 2014-2016 the libsecp256k1 contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoin;

/**
 * This class holds the context reference used in native methods 
 * to handle ECDSA operations.
 */
public class Secp256k1Context {
  private final boolean enabled; //true if the library is loaded
  private final long context; //ref to pointer to context obj

  public Secp256k1Context() {
    boolean isEnabled = true;
    long contextRef = -1;
    try {
      if ("The Android Project".equals(System.getProperty("java.vm.vendor"))) {
        System.loadLibrary("secp256k1");
      } else {
        fr.acinq.Secp256k1Loader.initialize();
      }
      contextRef = secp256k1_init_context();
    } catch (java.lang.UnsatisfiedLinkError e) {
      System.out.println("Cannot load secp256k1 native library: " + e.toString());
      isEnabled = false;
    } catch (Exception e) {
      System.out.println("Cannot load secp256k1 native library: " + e.toString());
      isEnabled = false;
    }
    enabled = isEnabled;
    context = contextRef;
  }

  public boolean isEnabled() {
    return enabled;
  }

  public long getContext() {
    if(!enabled) return -1; //sanity check
    return context;
  }

  private static native long secp256k1_init_context();
}
