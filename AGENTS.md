# AGENTS.md

## Working style

- Any user request will be inside the file `agent/request/<request name>.md` you will be prompted to check `<request name>` and create a plan.
- If at any point during the creation of plan or execution you reach out for a tool but you cant find it. Add the tool to `agent/wishlist.md`
- Once the plan has been created you should store the plan inside `agent/plan/<plan name>_ACTIVE.md`. 
- Now when asked to execute Active Plan, you need to execute the plan with _ACTIVE suffix
- If at any point during the execution or the creation of plan you sense code smells or other unrelated issues which are not blockers then report them to `agent/review.md` file
- Before executing the plan you MUST run `agent-git` so that you get the correct git credentials.
- Post execution 
  - If the execution was successful, you should rename the plan to `agent/plan/<plan name>_COMPLETED.md`
  - If the execution was unsuccessful, you should rename the plan to `agent/plan/<plan name>_FAILED.md` and add a comment about what went wrong in the plan file.

## Commit Structure
- Make small incremental commits with clear commit messages following the formal "<type>(<scope>): <subject>" structure.
