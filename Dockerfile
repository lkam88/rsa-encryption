FROM maven:alpine
RUN mkdir -p rsa-encrpytion
WORKDIR rsa-encryption
COPY . .
RUN pwd
RUN mvn package
RUN ls -a
ENTRYPOINT ["java","-jar", "target/rsa-encryption.jar"]