-- CreateTable
CREATE TABLE "public"."PayrollTestResult" (
    "id" SERIAL NOT NULL,
    "testName" TEXT NOT NULL,
    "payloadIn" JSONB NOT NULL,
    "payloadOut" JSONB NOT NULL,
    "success" BOOLEAN NOT NULL DEFAULT false,
    "durationMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PayrollTestResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."PayrollCalculationLog" (
    "id" SERIAL NOT NULL,
    "runId" TEXT NOT NULL,
    "employeeId" TEXT,
    "period" TEXT,
    "input" JSONB NOT NULL,
    "output" JSONB NOT NULL,
    "errors" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PayrollCalculationLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."PayrollAutoCorrection" (
    "id" SERIAL NOT NULL,
    "ruleKey" TEXT NOT NULL,
    "before" JSONB NOT NULL,
    "after" JSONB NOT NULL,
    "reason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PayrollAutoCorrection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."PayrollPerformanceMetric" (
    "id" SERIAL NOT NULL,
    "metric" TEXT NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "labels" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PayrollPerformanceMetric_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."PayrollAutomatedTest" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "spec" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PayrollAutomatedTest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."Project" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "public"."Action" (
    "id" SERIAL NOT NULL,
    "projectId" INTEGER NOT NULL,
    "title" TEXT NOT NULL,
    "payload" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Action_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "PayrollTestResult_testName_idx" ON "public"."PayrollTestResult"("testName");

-- CreateIndex
CREATE INDEX "PayrollCalculationLog_runId_idx" ON "public"."PayrollCalculationLog"("runId");

-- CreateIndex
CREATE INDEX "PayrollCalculationLog_employeeId_idx" ON "public"."PayrollCalculationLog"("employeeId");

-- CreateIndex
CREATE INDEX "PayrollAutoCorrection_ruleKey_idx" ON "public"."PayrollAutoCorrection"("ruleKey");

-- CreateIndex
CREATE INDEX "PayrollPerformanceMetric_metric_idx" ON "public"."PayrollPerformanceMetric"("metric");

-- CreateIndex
CREATE UNIQUE INDEX "PayrollAutomatedTest_name_key" ON "public"."PayrollAutomatedTest"("name");

-- CreateIndex
CREATE INDEX "Action_projectId_idx" ON "public"."Action"("projectId");

-- AddForeignKey
ALTER TABLE "public"."Action" ADD CONSTRAINT "Action_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "public"."Project"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
