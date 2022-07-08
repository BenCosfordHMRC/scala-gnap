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

package builders

import models.get.{CISDeductions, CISSource, GetPeriodData}

object CISSourceBuilder {

  //scalastyle:off
  def customerCISSource(taxYear: Int): CISSource = CISSource(
    Some(400),Some(400),Some(400),Seq(
      CISDeductions(
        s"${taxYear-1}-04-06",
        s"$taxYear-04-05",
        Some("Contractor 1"),
        "111/11111",
        Some(200.00),
        Some(200.00),
        Some(200.00),
        Seq(
          GetPeriodData(
            s"${taxYear-1}-04-06",
            s"${taxYear-1}-05-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            Some("4557ecb5-fd32-48cc-81f5-e6acd1099f3c"),
            "customer"
          ),GetPeriodData(
            s"${taxYear-1}-05-06",
            s"${taxYear-1}-06-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            Some("4557ecb5-fd32-48cc-81f5-e6acd1099f3c"),
            "customer"
          )
        )
      ),CISDeductions(
        s"${taxYear-1}-04-06",
        s"$taxYear-04-05",
        Some("Contractor 2"),
        "222/11111",
        Some(200.00),
        Some(200.00),
        Some(200.00),
        Seq(
          GetPeriodData(
            s"${taxYear-1}-04-06",
            s"${taxYear-1}-05-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            Some("4557ecb5-fd32-48cc-81f5-e6acd1099f3c"),
            "customer"
          ),GetPeriodData(
            s"${taxYear-1}-05-06",
            s"${taxYear-1}-06-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            Some("4557ecb5-fd32-48cc-81f5-e6acd1099f3c"),
            "customer"
          )
        )
      )
    )
  )

  def contractorCISSource(taxYear: Int): CISSource = CISSource(
    Some(400),Some(400),Some(400),Seq(
      CISDeductions(
        s"${taxYear-1}-04-06",
        s"$taxYear-04-05",
        Some("Contractor 1"),
        "111/11111",
        Some(200.00),
        Some(200.00),
        Some(200.00),
        Seq(
          GetPeriodData(
            s"${taxYear-1}-04-06",
            s"${taxYear-1}-05-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            None,
            "contractor"
          ),GetPeriodData(
            s"${taxYear-1}-05-06",
            s"${taxYear-1}-06-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            None,
            "contractor"
          )
        )
      ),CISDeductions(
        s"${taxYear-1}-04-06",
        s"$taxYear-04-05",
        Some("Contractor 2"),
        "222/11111",
        Some(200.00),
        Some(200.00),
        Some(200.00),
        Seq(
          GetPeriodData(
            s"${taxYear-1}-04-06",
            s"${taxYear-1}-05-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            None,
            "contractor"
          ),GetPeriodData(
            s"${taxYear-1}-05-06",
            s"${taxYear-1}-06-05",
            Some(100.00),
            Some(100.00),
            Some(100.00),
            "2022-05-11T16:38:57.489Z",
            None,
            "contractor"
          )
        )
      )
    )
  )

}
