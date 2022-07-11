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
package crypto

import java.io.UnsupportedEncodingException
import java.nio.ByteBuffer
import java.nio.charset.Charset
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.SignatureException
import java.text.ParseException
import java.time.Instant
import java.util
import java.util.{ArrayList, Base64, LinkedHashMap, List, Map}
import java.util.stream.Collectors
import java.util.stream.Stream
import javax.servlet.http.HttpServletRequest
import org.bouncycastle.jcajce.provider.digest.SHA256
import org.bouncycastle.jcajce.provider.digest.SHA512
import org.greenbytes.http.sfv.ByteSequenceItem
import org.greenbytes.http.sfv.Dictionary
import org.greenbytes.http.sfv.ListElement
import org.slf4j.Logger
import org.slf4j.LoggerFactory
//import org.springframework.web.util.UriUtils
import com.google.common.base.Joiner
import com.google.common.base.Strings
import com.google.common.net.HttpHeaders
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObject
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import http.{DigestWrappingFilter, JoseUnwrappingFilter}
import io.bspk.httpsig.ComponentProvider
import io.bspk.httpsig.HttpSigAlgorithm
import io.bspk.httpsig.HttpVerify
import io.bspk.httpsig.SignatureBaseBuilder
import io.bspk.httpsig.SignatureParameters
import io.bspk.httpsig.servlet.HttpServletRequestProvider
//import io.bspk.oauth.xyz.http.DigestWrappingFilter
//import io.bspk.oauth.xyz.http.JoseUnwrappingFilter
import play.twirl.api.TwirlHelperImports.twirlJavaCollectionToScala

//scalastyle:off
sealed trait ErrorResponse
case object BadJWS extends ErrorResponse
case object NoJOSEObject extends ErrorResponse
case object MissingSignatureHeader extends ErrorResponse
case object MissingSignatureInputHeader extends ErrorResponse

object SignatureVerifier {
  private val log = LoggerFactory.getLogger(this.getClass)

  def checkAttachedJws(request: HttpServletRequest, clientKey: JWK): Boolean = {
    checkAttachedJws(request, clientKey, null)
  }

  def checkAttachedJws(request: HttpServletRequest, clientKey: JWK, accessToken: String): Boolean = {
    try {
      val jose = request.getAttribute(JoseUnwrappingFilter.BODY_JOSE).asInstanceOf[JOSEObject]
      jose match {
        case jws: JWSObject =>
          verifyJWS(jws, request, clientKey, accessToken)
          val verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jws.getHeader, extractKeyForVerify(clientKey))

          if (!jws.verify(verifier)) {
            log.info("Bad JWS")
            false
          } else { // note: we know the payload matches the body because of the JoseUnwrappingFilter extracted it
            true
          }
        case _ => false
      }
    } catch {
      case e: JOSEException =>
        log.info("Bad JWS")
        false
      case e: Exception =>
        log.info("No JOSE object detected")
        false
    }
  }

  def checkHttpMessageSignature(signature: Dictionary, signatureInput: Dictionary, request: HttpServletRequest, clientKey: JWK): Seq[Option[String]] = {
    try {
      (signature, signatureInput) match {
        case (null, _) => log.info("Missing signature header"); Seq.empty
        case (_, null) => log.info("Missing signature input header"); Seq.empty
        case (signature: Dictionary, signatureInput: Dictionary) =>
          val _signature = signature.get()
          signatureInput.get().keySet().map { sigId =>
            if (_signature.containsKey(sigId)) {
              val sigParams = SignatureParameters.fromDictionaryEntry(signatureInput, sigId)
              val sigValue = _signature.get(sigId).asInstanceOf[ByteSequenceItem]
              val savedBody = request.getAttribute(DigestWrappingFilter.BODY_BYTES).asInstanceOf[Array[Byte]]

              if (savedBody != null && savedBody.length > 0 && !sigParams.containsComponentIdentifier("content-digest")) { // missing the content-digest header
                log.info(s"Missing content-digest header on non-empty body")
                None
              } else {
                if (request.getHeader(HttpHeaders.AUTHORIZATION) != null && !sigParams.containsComponentIdentifier("authorization")) {
                  log.info(s"Missing authorization header on a token-protected call")
                  None
                } else {
                  if (sigParams.containsComponentIdentifier("@method") && sigParams.containsComponentIdentifier("@target-uri")) { // should we allow the URI in parts?
                    val ctx = new HttpServletRequestProvider(request)
                    // collect the base string
                    val baseBuilder = new SignatureBaseBuilder(sigParams, ctx)
                    val baseBytes = baseBuilder.createSignatureBase
                    val alg = sigParams.getAlg match {
                      case null => HttpSigAlgorithm.JOSE // FIXME: this needs to be signaled better
                      case _alg => _alg
                    }
                    val verify = new HttpVerify(alg, clientKey)
                    val bb = sigValue.get
                    val sigBytes = new Array[Byte](bb.remaining)
                    bb.get(sigBytes)
                    if (!verify.verify(baseBytes, sigBytes)) {
                      log.info("Bad Signature, no biscuit")
                      None
                    } else {
                      log.info(s"Verified signature for id $sigId")
                      Some(sigId)
                    }
                  } else {
                    log.info(s"Missing required covered component, found: ${sigParams.getComponentIdentifiers}")
                    None
                  }
                }
              }
            } else {
              log.info(s"Didn't find signature for id $sigId")
              None
            }
          }.toSeq
      }
    } catch {
      case e: Exception =>
        log.info(s"Exception: $e")
        Seq.empty
    }
  }

  def checkCavageSignature(signatureHeaderPayload: String, request: HttpServletRequest, clientKey: JWK): Option[String] = {
    if(signatureHeaderPayload.nonEmpty){
      try {
        val signatureParts = signatureHeaderPayload.split(",").toSeq.map { s => //Need to be streamed?
          val parts = s.split("=", 2)
          val noQuotes = parts(1).replaceAll("^\"([^\"]*)\"$", "$1")
          parts(0) -> noQuotes
        }.toMap

        val headersToSign: Seq[String] = signatureParts.get("headers").map(_.split(" ").toSeq).getOrElse(Seq.empty)

        val signatureBlock = headersToSign.flatMap {
          headerToSign =>
            if (headerToSign == "(request-target)") {
              val requestTarget = request.getMethod.toLowerCase + " " + request.getRequestURI
              Some(headerToSign.toLowerCase -> requestTarget)
            } else if (request.getHeader(headerToSign) != null) {
              Some(headerToSign.toLowerCase -> request.getHeader(headerToSign))
            } else {
              None
            }
        }

        val input = signatureBlock.map(signature => signature._1.strip.toLowerCase + ": " + signature._2.strip()).mkString("\n")
        val rsaKey = clientKey.asInstanceOf[RSAKey]
        val signature = Signature.getInstance("SHA256withRSA")
        val signatureBytes = Base64.getDecoder.decode(signatureParts("signature"))

        signature.initVerify(rsaKey.toPublicKey)
        signature.update(input.getBytes("UTF-8"))

        if (signature.verify(signatureBytes)) {
          log.info("++ Verified Cavage signature")
          Some(input)
        } else {
          log.info("Bad Signature, no biscuit")
          None
        }
      } catch {
        case e@(_: NoSuchAlgorithmException | _: InvalidKeyException | _: JOSEException | _: SignatureException | _: UnsupportedEncodingException) =>
          log.info(s"Bad crypto, no biscuit $e")
          None
      }
    } else {
      log.info("signatureHeaderPayload is null or empty")
      None
    }
  }

  def checkDetachedJws(jwsd: String, request: HttpServletRequest, jwk: JWK, accessToken: String): Option[String] = {
    if(jwsd.nonEmpty){
      try {
        val body = request.getAttribute(DigestWrappingFilter.BODY_BYTES).asInstanceOf[Array[Byte]]

        val encodedHash = new Hash().SHA256_encode_url(body)
        val payload = encodedHash match {
          case Some(encodedHash) => new Payload(encodedHash)
          case None => new Payload(new Array[Byte](0))
        }

        val jwsObject = JWSObject.parse(jwsd)
        if (!(payload.toBase64URL == jwsObject.getPayload.toBase64URL)){
          log.info(s"Body hash did not match. Expected ${payload.toBase64URL.toString} received ${jwsObject.getPayload.toBase64URL.toString}")
          None
        } else {
          log.info("++ Verified Detached JWS signature")
          verifyJWS(jwsObject, request, jwk, accessToken)
        }
      } catch {
        case e@(_: ParseException | _: JOSEException) =>
          log.info(s"Bad JWS ${e}")
          None
      }
    } else {
      log.info("Missing JWS value")
      None
    }
  }

  private def verifyJWS(jwsObject: JWSObject, request: HttpServletRequest, jwk: JWK, accessToken: String): Option[String] = {

    try {
      val header = jwsObject.getHeader
      val verifier = new DefaultJWSVerifierFactory().createJWSVerifier(header, extractKeyForVerify(jwk))

      if (jwsObject.verify(verifier)) {
        // check the URI and method
        if (header.getCustomParam("htm") == null || !(header.getCustomParam("htm").asInstanceOf[String] == request.getMethod)) {
          log.info("Couldn't verify method")
          None
        } else {
          if (header.getCustomParam("uri") == null) {
            log.info("Couldn't get uri")
            None
          } else {

            val url = request.getRequestURL.toString
            val fullUrl: String = if (request.getQueryString != null) s"$url?${request.getQueryString}" else url
            if (header.getCustomParam("uri") != fullUrl) {
              log.info("Couldn't verify uri")
              None
            } else {
              if (accessToken.nonEmpty) {
                if (header.getCustomParam("ath") != null) {
                  val expected = new Hash().SHA256_encode_url(accessToken.getBytes)
                  val actual = Base64URL.from(header.getCustomParam("ath").toString)
                  if (expected.contains(actual)) {
                    Some(actual.toString)
                  } else {
                    log.info(s"Access token hash does not match: $expected / $actual")
                    None
                  }
                } else {
                  log.info("Couldn't get access token hash")
                  None
                }
              } else {
                log.info("Access token is empty")
                None
              }
            }
          }
        }
      } else {
        log.info("Unable to verify JWS")
        None
      }
    } catch {
      case jose: JOSEException =>
        log.info(s"JOSEException $jose")
        None
      case e: Exception =>
        log.info(s"Exception: $e")
        None
    }
  }

  def checkDpop(dpop: String, request: HttpServletRequest, clientKey: JWK, accessToken: String): Option[String] = {
    try {
      val jwt = SignedJWT.parse(dpop)
      val jwtKey = jwt.getHeader.getJWK

      if(jwtKey == clientKey){
        val verifier = new DefaultJWSVerifierFactory().createJWSVerifier(jwt.getHeader, extractKeyForVerify(clientKey))

        if(jwt.verify(verifier)){
          val claims = jwt.getJWTClaimsSet

          if (claims.getClaim("htm") == null || !(claims.getClaim("htm") == request.getMethod)){
            log.info("Couldn't verify method")
            None
          } else {
            if (claims.getClaim("htu") == null){
              log.info("Couldn't get uri")
              None
            } else {
              val url = request.getRequestURL.toString
              val fullUrl = if (request.getQueryString != null) s"$url?${request.getQueryString}" else url
              if(claims.getClaim("htu") != fullUrl) {
                log.info("Couldn't verify uri")
                None
              } else {
                val digest = if (claims.getClaim("digest") != null)Some(ensureDigest(claims.getClaim("digest").toString, request))else None
                if(digest.isEmpty || digest.contains(true)){
                  if (accessToken.nonEmpty) {
                    if (claims.getClaim("ath") != null) {
                      val expected = new Hash().SHA256_encode_url(accessToken.getBytes)
                      val actual = Base64URL.from(claims.getStringClaim("ath"))
                      if (expected.contains(actual)) {
                        log.info("++ Verified DPoP signature")
                        Some(actual.toString)
                      } else {
                        log.info(s"Access token hash does not match: $expected / $actual")
                        None
                      }
                    } else {
                      log.info("Couldn't get access token hash")
                      None
                    }
                  } else {
                    log.info("Access token is empty")
                    None
                  }
                } else {
                  log.info("Bad digest")
                  None
                }
              }
            }
          }
        } else {
          log.info("Unable to verify DPOP Signature")
          None
        }
      } else {
        log.info("Client key did not match DPoP key")
        None
      }
    } catch {
      case e@(_: ParseException | _: JOSEException) =>
        log.info("Bad DPOP Signature", e)
        None
    }
  }

  def checkHeaderHash(request: HttpServletRequest, headersUsed: Seq[String], hashUsed: String): Option[String] = {
    try {
      if(headersUsed != null && hashUsed.nonEmpty){
        val hashBase = headersUsed.map{ headerUsed =>
          val first = request.getHeader(headerUsed)
          s"${headerUsed.toLowerCase}: $first"
        }

        val hash = new Hash().SHA256_encode(hashBase.mkString("\n"))
        if(hash.contains(hashUsed)){
          log.info("++ Validated header hash")
          hash
        } else {
          log.info(s"Couldn't validate header hash: $hash / hashUsed: $hashUsed")
          None
        }
      } else {
        log.info("Invalid header or hash")
        None
      }
    } catch {
      case e: Exception =>
        log.info(s"Exception: $e")
        None
    }
  }

  def checkClaimValueIfExists(claims: JWTClaimsSet, req: HttpServletRequest, value: String, f:(HttpServletRequest, Seq[String], String) => Option[String]): Option[Boolean] ={
    if (claims.getClaim(value) != null) {
      val q = claims.getClaim(value).asInstanceOf[util.List[AnyRef]]
      f(req, q.get(0).asInstanceOf[util.List[String]].toSeq, q.get(1).asInstanceOf[String]) match { //TODO change
        case Some(_) => Some(true)
        case None => Some(false)
      }
    } else {
      None
    }
  }

  def claimCheckValueIfExists(claims: JWTClaimsSet, value: String, f: () => String): Option[Boolean] = {
    lazy val message = value match {
      case "m" => "method"
      case "u" => "host"
      case "p" => "path"
    }

    val claim = claims.getClaim(value)
    if(claim != null){
      if(f() == claim){
        Some(true)
      } else {
        log.info(s"Couldn't validate $message.")
        Some(false)
      }
    } else {
      None
    }
  }

  def checkTimestamp(claims: JWTClaimsSet): Option[Boolean] ={
    if (claims.getClaim("ts") != null) {
      val ts = Instant.ofEpochSecond(claims.getLongClaim("ts"))
      if (!Instant.now.minusSeconds(10).isBefore(ts) || !Instant.now.plusSeconds(10).isAfter(ts)){
        log.info("Timestamp outside of acceptable window.")
        Some(false)
      } else {
        Some(true)
      }
    } else {
      None
    }
  }

  def checkSkippedOrIsValid(check: Option[Boolean]): Boolean = check.isEmpty || check.contains(true)

  def checkOAuthPop(oauthPop: String, req: HttpServletRequest, jwk: JWK, accessToken: String): Option[String] = {
    try {
      val jwt = SignedJWT.parse(oauthPop)
      val claims = jwt.getJWTClaimsSet

      val query = checkClaimValueIfExists(claims,req,"q",checkQueryHash)
      val header = checkClaimValueIfExists(claims,req,"h",checkHeaderHash)

      if(checkSkippedOrIsValid(query) && checkSkippedOrIsValid(header)){

        val method = claimCheckValueIfExists(claims, "m", req.getMethod)
        val host = claimCheckValueIfExists(claims, "u", req.getServerName)
        val path = claimCheckValueIfExists(claims, "p", req.getRequestURI)

        if(checkSkippedOrIsValid(method) && checkSkippedOrIsValid(host) && checkSkippedOrIsValid(path)){
          if(checkSkippedOrIsValid(checkTimestamp(claims))){

            if(accessToken.nonEmpty && claims.getClaim("at") != null){
              if(claims.getClaim(accessToken) == accessToken) {
                log.info("++ Verified OAuth PoP")
                Some(accessToken)
              } else{
                log.info(s"Access token didn't match. (And that's really weird considering how we got here.) $accessToken / ${claims.getClaim(accessToken)}")
                None
              }
            } else {
              log.info("No access token")
              None
            }
          } else {
            log.info("Claim timestamp check failed")
            None
          }
        } else {
          log.info("Claim checks failed")
          None
        }
      } else {
        log.info("Query or hash check failed")
        None
      }
    } catch {
      case e: ParseException =>
        log.info("Couldn't parse pop header", e)
        None
      case e: Exception =>
        log.info(s"Exception: $e")
        None
    }
  }

  @throws[JOSEException]
  private def extractKeyForVerify(jwk: JWK) = if (jwk.isInstanceOf[OctetSequenceKey]) jwk.toOctetSequenceKey.toSecretKey
  else if (jwk.isInstanceOf[RSAKey]) jwk.toRSAKey.toPublicKey
  else if (jwk.isInstanceOf[ECKey]) jwk.toECKey.toECPublicKey
  else if (jwk.isInstanceOf[OctetKeyPair]) jwk.toOctetKeyPair.toPublicKey
  else throw new JOSEException("Unable to create signer for key: " + jwk)

  private def checkQueryHash(request: HttpServletRequest, paramsUsed: Seq[String], hashUsed: String): Option[String] = {
//    if (paramsUsed != null && !Strings.isNullOrEmpty(hashUsed)) {
//      val hashBase = new util.ArrayList[String]
//      paramsUsed.forEach((q: String) => {
//        def foo(q: String) = {
//          val first = request.getParameter(q)
//          hashBase.add(UriUtils.encodeQueryParam(q, Charset.defaultCharset) + "=" + UriUtils.encodeQueryParam(first, Charset.defaultCharset))
//        }
//
//        foo(q)
//      })
//      val hash = new Hash().SHA256_encode(Joiner.on("&").join(hashBase))
//      if (!(hash == hashUsed)) throw new RuntimeException("Couldn't validate query hash")
//      log.info("++ Validated query hash")
//    }
    ???
  }

  /**
   * @param digest
   * @param req
   */
  def ensureDigest(digestHeader: String, req: HttpServletRequest): Boolean = {
    if (digestHeader != null) if (digestHeader.startsWith("SHA=")) {
      val savedBody = req.getAttribute(DigestWrappingFilter.BODY_BYTES).asInstanceOf[Array[Byte]]
      if (savedBody == null || savedBody.length == 0) throw new RuntimeException("Bad Digest, no body")
      val actualHash = new Hash().SHA1_digest(savedBody)
      val incomingHash = digestHeader.substring("SHA=".length)
      if (!(actualHash.contains(incomingHash))) throw new RuntimeException("Bad Digest, no biscuit")
    }
    else throw new RuntimeException("Bad digest, unknown algorithm")
    log.info("++ Verified body digest")
    false
  }

  def ensureContentDigest(contentDigestHeader: Dictionary, req: HttpServletRequest): Unit = {
//    val savedBody = req.getAttribute(DigestWrappingFilter.BODY_BYTES).asInstanceOf[Array[Byte]]
//    if (savedBody == null || savedBody.length == 0) if (contentDigestHeader == null)
//    else throw new RuntimeException("Bad Content Digest, no body")
//    else {
//      val m = contentDigestHeader.get
//      import scala.collection.JavaConversions._
//      for (alg <- m.keySet) {
//        if (alg == "sha-512") {
//          val sha = new SHA512.Digest
//          val digest = sha.digest(savedBody)
//          val expected = ByteBuffer.wrap(digest)
//          val actual = m.get(alg).asInstanceOf[ByteSequenceItem].get
//          if (!(expected == actual)) throw new RuntimeException("Bad Content Digest, no biscuit")
//        }
//        else if (alg == "sha-256") {
//          val sha = new SHA256.Digest
//          val digest = sha.digest(savedBody)
//          val expected = ByteBuffer.wrap(digest)
//          val actual = m.get(alg).asInstanceOf[ByteSequenceItem].get
//          if (!(expected == actual)) throw new RuntimeException("Bad Content Digest, no biscuit")
//        }
//        else throw new RuntimeException("Bad Content digest, unknown algorithm: " + alg)
//      }
//      log.info("++ Verified body content-digest")
//    }
    ???
  }

  def extractBoundAccessToken(auth: String, oauthPop: String): String = { // if there's an OAuth PoP style presentation, use that header's internal value
    if (!Strings.isNullOrEmpty(oauthPop)) try {
      val jwt = SignedJWT.parse(oauthPop)
      val claims = jwt.getJWTClaimsSet
      val at = claims.getStringClaim("at")
      Strings.emptyToNull(at)
    } catch {
      case e: ParseException =>
        log.error("Unable to parse OAuth PoP to look for token", e)
        null
    }
    else if (Strings.isNullOrEmpty(auth)) null
    else if (!auth.startsWith("GNAP ")) null
    else auth.substring("GNAP ".length)
  }
}
