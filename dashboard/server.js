import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import cors from "cors";
import express from "express";

import { toDashboardResult } from "./analysis-adapter.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = 5000;
const REPOSITORY_ROOT = path.resolve(__dirname, "..");
const RUNS_DIRECTORY = path.join(__dirname, "runs");
const ANALYSIS_TIMEOUT_MS = 30 * 60 * 1000;

app.use(cors());
app.use(express.json());

app.post("/api/analyze", async (req, res) => {
  const source = req.body?.url;

  if (typeof source !== "string" || source.trim() === "") {
    return res.status(400).json({
      error: "A GitHub repository URL is required.",
    });
  }

  const normalizedSource = source.trim();
  const runId = randomUUID();
  const runDirectory = path.join(RUNS_DIRECTORY, runId);
  const workDirectory = path.join(runDirectory, "work");
  const analysisOutput = path.join(runDirectory, "analysis.json");
  const vexOutput = path.join(runDirectory, "openvex.json");

  try {
    await fs.mkdir(runDirectory, { recursive: true });

    console.log(`[${runId}] Analysis started: ${normalizedSource}`);

    await runReveal({
      source: normalizedSource,
      workDirectory,
      analysisOutput,
      vexOutput,
    });

    const rawData = await fs.readFile(analysisOutput, "utf8");
    const analysisData = JSON.parse(rawData);

    const dashboardResult = toDashboardResult(analysisData, {
      source: normalizedSource,
    });

    console.log(`[${runId}] Analysis completed`);

    return res.json(dashboardResult);
  } catch (error) {
    console.error(`[${runId}] Analysis failed:`, error);

    const detail =
      error instanceof Error
        ? error.message
        : "An unknown error occurred.";

    return res.status(500).json({
      error: "REVEAL analysis failed.",
      detail,
    });
  }
});

function runReveal({
  source,
  workDirectory,
  analysisOutput,
  vexOutput,
}) {
  return new Promise((resolve, reject) => {
    const argumentsList = [
      "analyze",
      source,
      "--work-dir",
      workDirectory,
      "--analysis-output",
      analysisOutput,
      "--vex-output",
      vexOutput,
    ];

    const child = spawn("reveal", argumentsList, {
      cwd: REPOSITORY_ROOT,
      env: process.env,
      shell: false,
    });

    let stderr = "";
    let timedOut = false;

    child.stdout.on("data", (chunk) => {
      process.stdout.write(chunk);
    });

    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();

      process.stderr.write(text);
      stderr = `${stderr}${text}`.slice(-10_000);
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, ANALYSIS_TIMEOUT_MS);

    child.on("error", (error) => {
      clearTimeout(timeout);

      reject(
        new Error(
          `Failed to start the REVEAL CLI: ${error.message}`,
        ),
      );
    });

    child.on("close", (exitCode) => {
      clearTimeout(timeout);

      if (timedOut) {
        reject(
          new Error(
            `Analysis exceeded the ${
              ANALYSIS_TIMEOUT_MS / 60_000
            } minute timeout.`,
          ),
        );
        return;
      }

      if (exitCode !== 0) {
        reject(
          new Error(
            stderr.trim() ||
              `REVEAL CLI exited with code ${exitCode}.`,
          ),
        );
        return;
      }

      resolve();
    });
  });
}

const server = app.listen(PORT, () => {
  console.log(
    `Backend server running at http://localhost:${PORT}`,
  );
});

server.requestTimeout = 0;