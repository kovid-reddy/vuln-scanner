-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "checks" TEXT[] DEFAULT ARRAY[]::TEXT[];
