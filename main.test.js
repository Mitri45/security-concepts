import { fireEvent, screen } from "@testing-library/dom";
import { beforeEach, describe, expect, it } from "vitest";
import { populateConceptList, securityConcepts } from "./main.js";

// Set up the DOM before each test
beforeEach(() => {
	document.body.innerHTML = `
    <aside id="concept-list">
      <ul></ul>
    </aside>
    <h2 id="concept-title"></h2>
    <p id="concept-description"></p>
    <div id="interactive-area"></div>
    <div id="threejs-canvas-container"></div>
  `;
});

describe("populateConceptList", () => {
	it("renders a button for each security concept", () => {
		populateConceptList();
		// All buttons should be rendered inside the list
		const buttons = screen.getAllByRole("button");
		expect(buttons.length).toBe(securityConcepts.length);
		// Check first button text matches first concept title
		expect(buttons[0].textContent).toBe(securityConcepts[0].title);
	});
});

describe("handleConceptClick", () => {
	it("updates the concept title and description when a concept is clicked", () => {
		populateConceptList();
		const buttons = screen.getAllByRole("button");
		// Click the second concept
		fireEvent.click(buttons[1]);

		// Check if title and description updated
		const titleEl = screen.getByText(securityConcepts[1].title);
		const descEl = screen.getByText(securityConcepts[1].description);
		expect(titleEl).toBeTruthy();
		expect(descEl).toBeTruthy();
	});
});
