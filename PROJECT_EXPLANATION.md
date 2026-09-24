# Project Explanation: CloudTrail Insider Threat Detection

## The Core Problem

When you use a cloud platform like AWS, every single action taken by any user or service is recorded in an audit log called **CloudTrail**. These logs are massive. 

The hardest security problem to solve is finding an **insider threat**. This is when someone who has valid access (like an employee, or a hacker who stole an employee's password) starts doing bad things. Because they are using valid credentials, they don't trigger normal security alarms like a failed login would.

Current machine learning models (like an Isolation Forest or an Autoencoder) try to find anomalies in these logs. However, they have two major real-world problems:
1. **The Alert Budget:** A real security team only has time to investigate a small number of alerts per day (e.g., 10 alerts). Most standard models give high anomaly scores to "noisy" accounts (like automated service accounts that do thousands of tasks). These noisy accounts fill up the top 10 spots every day, hiding the actual threats.
2. **Lack of Context:** Even if a model flags an action as suspicious, if it just says "Score: 0.99" without explaining *why*, a human analyst won't know how to investigate it. They will likely ignore it.

---

## The Solution & First Principles

To fix this, this project introduces a new detection system called **BudgetAwareConformal**. It is built on four core principles (or steps):

### 1. Compare People to Themselves (Per-Principal Surprisal)
Instead of comparing what a user is doing against *everybody else in the company*, the system compares the user's current actions against *their own past behavior*. 
- It breaks behavior down into categories (families): **Volume** (how much they are doing), **Diversity** (how many different things they are touching), and **Temporal** (when they are doing it).
- It trains a tiny, separate anomaly detector for each user and each category.

### 2. Make Scores Fair (Conformal Calibration)
A raw anomaly score of "10" means something different for a noisy service account than it does for a quiet human user. To rank who is the *most* suspicious company-wide, we must compare apples to apples.
- The system takes the raw scores and converts them into **p-values** (a standard scale from 0 to 1) based on that specific user's history. 
- Now, an anomaly score means the exact same thing regardless of who generated it.

### 3. Combine Weak Signals (Fisher Fusion)
Sometimes an insider tries to be stealthy. They might do slightly more actions than normal, touch slightly different resources, at a slightly weirder time. No single action is weird enough to trigger an alarm on its own.
- The system uses a mathematical technique called **Fisher's method** to combine these slight anomalies. 
- If a user is slightly weird in three different ways at the exact same time, the system fuses those signals into one major red flag.

### 4. Respect the Security Team's Time (Budget-Aware Selector)
If we only have time to look at 10 alerts today, we don't want all 10 to be the same user doing the same weird thing 10 times.
- The system groups weird events together by user and day. 
- It also suppresses alerts if a user was already flagged yesterday. 
- This ensures that the limited "budget" of 10 alerts is spent looking at 10 *distinct* potential threats.

---

## What Has Been Built So Far?

The entire system has been built into a clean, automated pipeline. You can run the entire project from start to finish using one script (`run_pipeline.py`).

Here is what the code currently does automatically:
1. **Data Generation:** It creates a highly realistic, synthetic dataset of 1,000 users over 180 days, and hides 4 specific types of insider threats inside it.
2. **Data Normalization:** It cleans up the log data so the column names always match a standard format.
3. **Feature Engineering:** It calculates the volume, diversity, and temporal behaviors for everyone.
4. **Model Training:** It trains standard industry baselines (Isolation Forest, Local Outlier Factor, Autoencoders, and basic Rules) alongside the new **BudgetAwareConformal** model.
5. **Evaluation:** It scores all the models to see how many threats they actually catch if the security team only looks at the top 10, 50, or 100 alerts.
6. **Explanations:** It uses a tool called SHAP to generate plain-English explanations for *why* an alert was fired (e.g., "This user accessed 5 times more S3 buckets than usual").
7. **Reporting:** It automatically generates charts, graphs, and metric files comparing the new model to the baselines.

In short, the project is a fully functional testbed and proof-of-concept that proves evaluating security alerts relative to a user's own history, and fusing those scores fairly, produces much better results for a busy security team.
