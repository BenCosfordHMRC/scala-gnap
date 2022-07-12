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

package data.api

import com.nimbusds.jose.jwk.JWK
import data.{Key, Proof}

import java.net.URI
import java.security.cert.X509Certificate

case class KeyRequest(proof: Option[Proof],
                      cert: Option[X509Certificate],
                      did: Option[URI],
                      jwk: Option[JWK])

object KeyRequest {
  def apply(key: Key): KeyRequest ={
    KeyRequest(
      jwk = key.jwk.map(_.toPublicJWK), // make sure we only ever pass a public key in the request
      proof = key.proof,
      cert = key.cert,
      did = key.did
    )
  }
}
