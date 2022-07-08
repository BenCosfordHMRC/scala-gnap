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

import data.api.{HandleAwareField, RequestedResource}
import org.apache.commons.lang3.RandomStringUtils

import java.time.{Duration, Instant}

case class AccessToken(value: String,
                       key: Option[Key] = None,
                       bound: Boolean = false,
                       clientBound: Boolean = false,
                       manage: Option[String] = None,
                       accessRequest: Seq[HandleAwareField[RequestedResource]] = Seq.empty,
                       expiration: Option[Instant] = None,
                       label: Option[String] = None)

object AccessToken {

  val numericSize = 64

  private def create: AccessToken = {
    AccessToken(
      value = RandomStringUtils.randomAlphanumeric(numericSize)
    )
  }

  def create(lifetime: Duration): AccessToken = create.copy(expiration = Some(Instant.now.plus(lifetime)))

  def createClientBound(key: Key): AccessToken = create.copy(
    key = Some(key),
    bound = true,
    clientBound = true
  )
}
