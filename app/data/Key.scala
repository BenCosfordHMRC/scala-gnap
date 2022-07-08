/*
 * Copyright 2020 HM Revenue & Customs
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

package data

import com.nimbusds.jose.jwk.JWK
import data.api.{HandleAwareField, KeyRequest}

import java.net.URI
import java.security.cert.X509Certificate


sealed trait Proof
case object JWSD extends Proof
case object MTLS extends Proof
case object HTTPSIG extends Proof
case object DPOP extends Proof
case object OAUTHPOP extends Proof
case object JWS extends Proof

case class Key(proof: Option[Proof],
               cert: Option[X509Certificate],
               did: Option[URI],
               jwk: Option[JWK])

object Key {
  def apply(request: HandleAwareField[KeyRequest]): Option[Key] = {

    request match {
      case HandleAwareField(true, _, _) => None // TODO: dereference keys using a service
      case HandleAwareField(_, _, Some(data)) =>
        Some(Key(
          proof = data.proof,
          cert = data.cert,
          did = data.did,
          jwk = data.jwk
        ))
      case _ => None
    }
  }
}