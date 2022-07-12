/*
 * Copyright 2022 HM Revenue & Customs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package crypto

import com.google.common.base.Joiner
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jcajce.provider.digest.{SHA1, SHA256, SHA3, SHA512}

import java.net.URI
import java.security.MessageDigest
import java.util.Base64

case class HashMethod(name: String, function: String => String)

object HashMethod {

  val _SHA3: HashMethod = HashMethod("sha3", encodeSHA3512)
  val _SHA2: HashMethod = HashMethod("sha2", encodeSHA2512)

  private def encodeSHA3512(input: String): String = {
    val digest: MessageDigest = new SHA3.Digest512
    val output: Array[Byte] = digest.digest(input.getBytes)
    val encoded: Array[Byte] = Base64.getUrlEncoder.withoutPadding.encode(output)
    new String(encoded)
  }

  private def encodeSHA2512(input: String): String = {
    val output: Array[Byte] = digestSHA2512(input.getBytes)
    val encoded: Array[Byte] = Base64.getUrlEncoder.withoutPadding.encode(output)
    new String(encoded)
  }

  private def digestSHA2512(input: Array[Byte]): Array[Byte] = {
    val digest: MessageDigest = new SHA512.Digest
    val output: Array[Byte] = digest.digest(input)
    output
  }
}

//scalastyle:off
class Hash {

  private val newLineSeparator = '\n'


//    @JsonCreator def fromJson(key: String): Hash.HashMethod = {
//      return if (key == null) {
//        null
//      }
//      else {
//        valueOf(key.toUpperCase)
//      }
//    }
//
//    @JsonValue def toJson: String = {
//      return name.toLowerCase
//    }

  def calculateInteractHash(clientNonce: String, serverNonce: String, interact: String, endpointUri: URI, hashMethod: HashMethod): String = {
    hashMethod.function(Joiner.on(newLineSeparator).join(clientNonce, serverNonce, interact, endpointUri.toString))
  }

  def SHA256_encode(input: String): Option[String] = {
    if (input == null || input.isEmpty) {
      None
    } else {
      val digest: MessageDigest = new SHA256.Digest
      val output: Array[Byte] = digest.digest(input.getBytes)
      val encoded: Array[Byte] = Base64.getUrlEncoder.withoutPadding.encode(output)
      Some(new String(encoded))
    }
  }

  def SHA1_digest(input: Array[Byte]): Option[String] = {
    if (input == null || input.length == 0) {
      None
    } else {
      val digest: MessageDigest = new SHA1.Digest
      val output: Array[Byte] = digest.digest(input)
      val encoded: Array[Byte] = Base64.getEncoder.encode(output)
      Some(new String(encoded))
    }
  }

  // does a sha256 hash
  def SHA256_encode_url(input: Array[Byte]): Option[Base64URL] = {
    if (input == null || input.length == 0) {
      None
    } else {
      val digest: MessageDigest = new SHA256.Digest
      val output: Array[Byte] = digest.digest(input)
      val encodedHash: Base64URL = Base64URL.encode(output)
      Some(encodedHash)
    }
  }
}
