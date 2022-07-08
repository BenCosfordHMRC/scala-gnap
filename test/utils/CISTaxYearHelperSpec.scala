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

package utils

import models.CISDates

class CISTaxYearHelperSpec extends TestUtils {

  "CISTaxYearHelper" should {

    "return a cis dates model containing the correct dates when a tax year is passed" in {
      val taxYear = 2020
      val result = CISTaxYearHelper.cisTaxYearConverter(taxYear)
      result mustBe CISDates(fromDate = "2019-04-06", toDate = "2020-04-05")
    }
  }
}
