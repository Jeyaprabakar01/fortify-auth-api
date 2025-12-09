/*
  Warnings:

  - The values [VERIFICATION,RESET] on the enum `OTPType` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "OTPType_new" AS ENUM ('ACCOUNT_VERIFICATION', 'EMAIL_VERIFICATION', 'PASSWORD_RESET');
ALTER TABLE "otps" ALTER COLUMN "type" TYPE "OTPType_new" USING ("type"::text::"OTPType_new");
ALTER TYPE "OTPType" RENAME TO "OTPType_old";
ALTER TYPE "OTPType_new" RENAME TO "OTPType";
DROP TYPE "public"."OTPType_old";
COMMIT;
