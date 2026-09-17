// =========================================================
// CAMPUS HARDWARE INVENTORY
// WEB JAVASCRIPT
// =========================================================


// =========================================================
// PAGE READY
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        setupPasswordToggles();

        setupRequestForm();

    }
);


// =========================================================
// PASSWORD TOGGLE
// =========================================================

function setupPasswordToggles() {

    document
        .querySelectorAll(
            "[data-toggle-password]"
        )
        .forEach(
            function (checkbox) {

                checkbox.addEventListener(
                    "change",
                    function () {

                        const selector =
                            checkbox.dataset
                                .togglePassword;

                        const input =
                            document.querySelector(
                                selector
                            );

                        if (input) {

                            input.type =
                                checkbox.checked
                                    ? "text"
                                    : "password";

                        }

                    }
                );

            }
        );


    document
        .querySelectorAll(
            "[data-toggle-passwords]"
        )
        .forEach(
            function (checkbox) {

                checkbox.addEventListener(
                    "change",
                    function () {

                        const selectors =
                            checkbox.dataset
                                .togglePasswords
                                .split(",");

                        selectors.forEach(
                            function (selector) {

                                const input =
                                    document.querySelector(
                                        selector.trim()
                                    );

                                if (input) {

                                    input.type =
                                        checkbox.checked
                                            ? "text"
                                            : "password";

                                }

                            }
                        );

                    }
                );

            }
        );

}


// =========================================================
// REQUEST FORM
// =========================================================

function setupRequestForm() {

    const rowsContainer =
        document.getElementById(
            "equipmentRows"
        );

    const addButton =
        document.getElementById(
            "addEquipment"
        );

    if (!rowsContainer) {

        return;

    }


    // ------------------------------------------------------
    // ITEM SELECTION
    // ------------------------------------------------------

    rowsContainer.addEventListener(
        "change",
        function (event) {

            if (
                event.target.classList
                    .contains(
                        "request-item"
                    )
            ) {

                updateEquipmentRow(
                    event.target
                        .closest(
                            ".equipment-row"
                        )
                );

            }

        }
    );


    // ------------------------------------------------------
    // QUANTITY INPUT
    // ------------------------------------------------------

    rowsContainer.addEventListener(
        "input",
        function (event) {

            if (
                event.target.classList
                    .contains(
                        "request-quantity"
                    )
            ) {

                enforceQuantity(
                    event.target
                );

            }

        }
    );


    // ------------------------------------------------------
    // REMOVE EQUIPMENT
    // ------------------------------------------------------

    rowsContainer.addEventListener(
        "click",
        function (event) {

            if (
                !event.target.classList
                    .contains(
                        "remove-equipment"
                    )
            ) {

                return;

            }


            const rows =
                rowsContainer.querySelectorAll(
                    ".equipment-row"
                );

            const row =
                event.target.closest(
                    ".equipment-row"
                );


            // Keep one row.
            if (rows.length === 1) {

                const item =
                    row.querySelector(
                        ".request-item"
                    );

                const category =
                    row.querySelector(
                        ".request-category"
                    );

                const quantity =
                    row.querySelector(
                        ".request-quantity"
                    );

                const hint =
                    row.querySelector(
                        ".quantity-hint"
                    );


                item.value = "";

                category.value = "";

                quantity.value = 1;

                quantity.removeAttribute(
                    "max"
                );

                hint.textContent =
                    "Select hardware first.";

                return;

            }


            row.remove();

        }
    );


    // ------------------------------------------------------
    // ADD EQUIPMENT
    // ------------------------------------------------------

    if (addButton) {

        addButton.addEventListener(
            "click",
            function () {

                const firstRow =
                    rowsContainer.querySelector(
                        ".equipment-row"
                    );

                if (!firstRow) {

                    return;

                }


                const newRow =
                    firstRow.cloneNode(
                        true
                    );


                newRow.querySelector(
                    ".request-item"
                ).value = "";


                newRow.querySelector(
                    ".request-category"
                ).value = "";


                newRow.querySelector(
                    ".request-quantity"
                ).value = 1;


                newRow.querySelector(
                    ".request-quantity"
                ).removeAttribute(
                    "max"
                );


                newRow.querySelector(
                    ".quantity-hint"
                ).textContent =
                    "Select hardware first.";


                rowsContainer.appendChild(
                    newRow
                );

            }
        );

    }


    // Initial setup.
    rowsContainer
        .querySelectorAll(
            ".equipment-row"
        )
        .forEach(
            updateEquipmentRow
        );

}


// =========================================================
// UPDATE EQUIPMENT ROW
// =========================================================

function updateEquipmentRow(
    row
) {

    if (!row) {

        return;

    }


    const item =
        row.querySelector(
            ".request-item"
        );

    const category =
        row.querySelector(
            ".request-category"
        );

    const quantity =
        row.querySelector(
            ".request-quantity"
        );

    const hint =
        row.querySelector(
            ".quantity-hint"
        );


    if (
        !item ||
        !category ||
        !quantity ||
        !hint
    ) {

        return;

    }


    const selected =
        item.options[
            item.selectedIndex
        ];


    if (
        !selected ||
        !selected.value
    ) {

        category.value = "";

        quantity.removeAttribute(
            "max"
        );

        hint.textContent =
            "Select hardware first.";

        return;

    }


    const selectedCategory =
        selected.dataset.category
        || "";


    const available =
        parseInt(
            selected.dataset.available
            || "0",
            10
        );


    // Automatically set category.
    category.value =
        selectedCategory;


    // ------------------------------------------------------
    // OUT OF STOCK
    // ------------------------------------------------------

    if (available <= 0) {

        quantity.max = 0;

        quantity.value = 0;

        quantity.disabled = true;

        hint.textContent =
            "This item is currently out of stock.";

        return;

    }


    // ------------------------------------------------------
    // AVAILABLE
    // ------------------------------------------------------

    quantity.disabled = false;

    quantity.max =
        available;


    if (
        !quantity.value ||
        parseInt(
            quantity.value,
            10
        ) < 1
    ) {

        quantity.value = 1;

    }


    enforceQuantity(
        quantity
    );


    hint.textContent =
        "Maximum available quantity: "
        + available;

}


// =========================================================
// ENFORCE QUANTITY
// =========================================================

function enforceQuantity(
    input
) {

    const max =
        parseInt(
            input.max || "0",
            10
        );


    let value =
        parseInt(
            input.value || "0",
            10
        );


    if (value < 1) {

        value = 1;

    }


    if (
        max > 0 &&
        value > max
    ) {

        value = max;

        alert(
            "Requested quantity cannot "
            + "exceed the available stock ("
            + max
            + ")."
        );

    }


    input.value =
        value;

}


// =========================================================
// QUICK BORROW CONFIRMATION
// =========================================================

function confirmBorrow(
    form
) {

    const quantity =
        form.querySelector(
            "[name='quantity']"
        );


    if (!quantity) {

        return true;

    }


    const value =
        parseInt(
            quantity.value || "0",
            10
        );


    const max =
        parseInt(
            quantity.max || "0",
            10
        );


    if (value < 1) {

        alert(
            "Borrow quantity must "
            + "be at least 1."
        );

        return false;

    }


    if (
        max > 0 &&
        value > max
    ) {

        alert(
            "Borrow quantity cannot "
            + "exceed "
            + max
            + "."
        );

        return false;

    }


    return confirm(
        "Submit this borrow request "
        + "for "
        + value
        + " unit(s)?"
    );

}


// =========================================================
// REQUEST FORM CONFIRMATION
// =========================================================

function confirmRequestSubmit() {

    const form =
        document.getElementById(
            "requestForm"
        );


    if (!form) {

        return true;

    }


    const rows =
        form.querySelectorAll(
            ".equipment-row"
        );


    let validRows = 0;


    for (
        const row
        of rows
    ) {

        const item =
            row.querySelector(
                ".request-item"
            );

        const quantity =
            row.querySelector(
                ".request-quantity"
            );


        if (
            !item ||
            !quantity ||
            !item.value
        ) {

            continue;

        }


        validRows += 1;


        const value =
            parseInt(
                quantity.value || "0",
                10
            );


        const max =
            parseInt(
                quantity.max || "0",
                10
            );


        if (value < 1) {

            alert(
                "Each requested quantity "
                + "must be at least 1."
            );

            return false;

        }


        if (
            max > 0 &&
            value > max
        ) {

            alert(
                "Requested quantity cannot "
                + "exceed "
                + max
                + "."
            );

            return false;

        }

    }


    if (validRows === 0) {

        alert(
            "Please add at least "
            + "one hardware item."
        );

        return false;

    }


    return confirm(
        "Submit this hardware request?\n\n"
        + "Inventory will NOT be deducted "
        + "until an Admin approves the request."
    );

}


// =========================================================
// SELECT ALL
// =========================================================

function toggleGroup(
    source,
    className
) {

    document
        .querySelectorAll(
            "." + className
        )
        .forEach(
            function (checkbox) {

                checkbox.checked =
                    source.checked;

            }
        );

}


// =========================================================
// ADMIN / USER SELECTION CONFIRMATION
// =========================================================

function confirmSelection(
    action
) {

    const checked =
        document.querySelectorAll(
            "input[name='loan_ids']:checked,"
            + " input[name='request_ids']:checked"
        );


    if (!checked.length) {

        alert(
            "Please select at least one record."
        );

        return false;

    }


    return confirm(
        "Are you sure you want to "
        + action
        + "?"
    );

}