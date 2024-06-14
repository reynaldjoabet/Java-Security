scalaVersion := "2.13.12"

name    := "Java-Security" := "Nginx"
version := "1.0"
// https://mvnrepository.com/artifact/software.amazon.cryptools/AmazonCorrettoCryptoProvider
libraryDependencies += "software.amazon.cryptools" % "AmazonCorrettoCryptoProvider" % "2.3.3"

// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
libraryDependencies += "org.bouncycastle" % "bcprov-jdk18on" % "1.78.1"
