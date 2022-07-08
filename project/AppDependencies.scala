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

import play.core.PlayVersion.current
import sbt._

object AppDependencies {

  private val bootstrapPlay28Version = "5.24.0"

  val compile: Seq[ModuleID] = Seq(
    "uk.gov.hmrc"                   %%  "bootstrap-backend-play-28"       % bootstrapPlay28Version,
    "com.fasterxml.jackson.module"  %%  "jackson-module-scala"            % "2.12.2",
    "com.nimbusds"                  %  "nimbus-jose-jwt"                  % "9.4.1",
    "org.apache.commons"            % "commons-lang3"                     % "3.12.0",
    "org.bouncycastle"              %  "bcpkix-jdk15on"                   % "1.60",
    "org.greenbytes.http"           %  "structured-fields"                % "0.4",
    "com.sailpoint"                 %  "ietf-subject-identifiers-model"   % "0.1.0",
    "io.bspk"                       %  "httpsig"                          % "0.0.4",
  )

  val test: Seq[ModuleID] = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-28"   % bootstrapPlay28Version    % Test,
    "com.typesafe.play"       %% "play-test"                % current                   % Test,
    "org.scalatest"           %% "scalatest"                % "3.2.9"                   % Test,
    "com.vladsch.flexmark"    %  "flexmark-all"             % "0.36.8"                  % "test, it",
    "org.scalatestplus.play"  %% "scalatestplus-play"       % "5.1.0"                   % "test, it",
    "com.github.tomakehurst"  %  "wiremock-jre8"            % "2.28.0"                  % "test, it",
    "org.scalamock"           %% "scalamock"                % "5.1.0"                   % Test
  )
}
