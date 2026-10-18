# Sus Or Bus

**Sus Or Bus** is an evidence-based website safety, privacy, and risk analyzer. Paste any link before clicking to receive a transparent 0–100 risk score, verdict (`BUS`, `MILDLY SUS`, or `SUS`), granular technical evidence, tracker disclosures, terms & privacy analysis, and an isolated sandbox preview.
        -
Sus Or Bus's main goal is to analyze if a online medium such as a site is safe or not. It works by using Beautiful Soup to fetch the page and then sending a Beautiful Soup scraper to every page indexed by Google Search Console. Alongside that, it also goes to multiple variations of terms and privacy page endings. After that, the data gets filtered and organized in different programs that are running in the code, and then it's presented neatly for the viewer, along with a logic score. No AI is involved in this process, and the black box uses open-source algorithms that are contained in this repository, and decision-making weighted algorithms.

Please note that this project is not vibe coded, but I like the round, glossy look better. Additionally, this project is not authorized for commercial use and is not compliant with HIPPA regulations. Please do not submit sensitive information to Sus Or Bus. 

The original prototype for Sus Or Bus was vibe coded, but the algorithm and non-vibe-coded project were developed at the Capital Hackathon by a hack club, which took place from Friday, October 16, to Sunday, October 18, 2026. I have now removed the AI-only black box from the previous prototype and have created an automation to sync changes on this repository to the algorithm and the more refined and better-looking Sus Or Bus that is partially vibe coded in terms of CSS and design. 

For reference, I did not transfer the CSS and design to VS Code and swap it to vercel because the Chrome extension and the iOS app rely on the same host for data coordination and datasets, making it hard to migrate.

Just for a last piece of clarification, this is not vibe coded, and the mainstream site is only vibe coded in terms of design. 

The Build-Base44-Bundle.js file helps sync base44 to this current repository for a different version of Sus Or Bus, which I am not planning on submitting to Capital. I do this because I want them to have the same backend algorithm, which is relatively simple. 
