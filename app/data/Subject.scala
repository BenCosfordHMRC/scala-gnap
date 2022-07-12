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

package data

import com.sailpoint.ietf.subjectidentifiers.model.{SubjectIdentifier, SubjectIdentifierFormats}
import data.api.SubjectRequest

import java.time.Instant

case class Subject(subIds: Seq[SubjectIdentifier],
                   assertions: Seq[Assertion],
                   updatedAt: Instant)

object Subject {

  def apply(request: SubjectRequest, user: User): Subject = {

    val subIdsRequest = request.subIdFormats

    lazy val containsIssuer = subIdsRequest.contains(SubjectIdentifierFormats.ISSUER_SUBJECT)
    lazy val containsEmail = subIdsRequest.contains(SubjectIdentifierFormats.EMAIL)
    lazy val containsPhoneNo = subIdsRequest.contains(SubjectIdentifierFormats.PHONE_NUMBER)
    lazy val containsOpaque = subIdsRequest.contains(SubjectIdentifierFormats.OPAQUE)

    lazy val issuerSubject = new SubjectIdentifier.Builder().format(SubjectIdentifierFormats.ISSUER_SUBJECT).subject(user.id).issuer(user.iss).build
    lazy val emailSubject = new SubjectIdentifier.Builder().format(SubjectIdentifierFormats.EMAIL).email(user.email).build()
    lazy val phoneSubject = new SubjectIdentifier.Builder().format(SubjectIdentifierFormats.PHONE_NUMBER).phoneNumber(user.phone).build()
    lazy val opaqueSubject = new SubjectIdentifier.Builder().format(SubjectIdentifierFormats.OPAQUE).id(user.id).build()

    val subIds: Seq[SubjectIdentifier] = Seq(
      if (containsIssuer) Some(issuerSubject) else None,
      if (containsEmail) Some(emailSubject) else None,
      if (containsPhoneNo) Some(phoneSubject) else None,
      if (containsOpaque) Some(opaqueSubject) else None
      // TODO: add other types
    ).flatten

    val assertionRequest = request.assertionFormats

    val assertions: Seq[Assertion] = if(assertionRequest.contains(OIDC_ID_TOKEN) && user.idToken.isDefined){
      Seq(
        Assertion(OIDC_ID_TOKEN, user.idToken.get.serialize()) // TODO, add additional formats
      )
    } else {
      Seq.empty
    }

    Subject(
      subIds = subIds,
      assertions = assertions,
      updatedAt = user.updatedAt
    )
  }
}