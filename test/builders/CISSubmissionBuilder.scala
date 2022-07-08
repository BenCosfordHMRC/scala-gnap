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

import example.models.PeriodData
import example.models.submission.CISSubmission

object CISSubmissionBuilder {

  val aPeriodData: PeriodData = PeriodData(
    deductionFromDate = "2021-04-06",
    deductionToDate = "2021-05-05",
    grossAmountPaid = Some(1),
    deductionAmount = 1,
    costOfMaterials = Some(1)
  )

  val anUpdateCISSubmission: CISSubmission = CISSubmission(
    employerRef = None,
    submissionId = Some("submissionId"),
    contractorName = None,
    periodData = Seq(
      aPeriodData
    )
  )

  val aCreateCISSubmission: CISSubmission = CISSubmission(
    contractorName = Some("ABC Steelworks"),
    employerRef = Some("123/AB123456"),
    submissionId = None,
    periodData = Seq(
      aPeriodData
    )
  )
}
